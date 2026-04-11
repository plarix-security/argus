import * as fs from 'fs';
import * as path from 'path';
import { FileLanguageRouter, fileLanguageRouter } from './file-language-router';
import { analyzePythonFile, analyzePythonFiles, ensureParserInitialized } from './python/detector';
import { analyzeTypeScriptFile, analyzeTypeScriptFiles, ensureTypeScriptParserInitialized } from './typescript/detector';
import { AFBFinding, AnalysisReport, AnalyzerConfig, FileAnalysisResult, SupportedLanguage, Severity } from '../types';
import { VERSION } from '../cli/version';

const DEFAULT_CONFIG: Required<AnalyzerConfig> = {
  include: ['**/*.py', '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
  exclude: ['**/node_modules/**', '**/.venv/**', '**/venv/**', '**/__pycache__/**', '**/dist/**', '**/build/**', '**/.git/**', '**/test/**', '**/tests/**', '**/*.test.*', '**/*.spec.*'],
  minConfidence: 0.7,
  maxFiles: Number.MAX_SAFE_INTEGER,
  changedFilesOnly: false,
};

export class AFBAnalyzer {
  private walker: FileLanguageRouter;
  private config: Required<AnalyzerConfig>;
  private initialized = false;

  constructor(config?: AnalyzerConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.walker = fileLanguageRouter;
  }

  async ensureInitialized() {
    if (!this.initialized) {
      await this.walker.initialize();
      await ensureParserInitialized();
      await ensureTypeScriptParserInitialized();
      this.initialized = true;
    }
  }

  analyzeFile(filePath: string): FileAnalysisResult {
    const language = this.walker.getLanguage(filePath);
    if (!language) return { file: filePath, language: 'python', findings: [], success: false, error: 'Unsupported file type', analysisTimeMs: 0 };
    const sourceCode = fs.readFileSync(filePath, 'utf-8');
    return language === 'python' ? analyzePythonFile(filePath, sourceCode) : analyzeTypeScriptFile(filePath, sourceCode);
  }

  analyzeSource(sourceCode: string, language: SupportedLanguage, virtualPath: string = '<source>'): FileAnalysisResult {
    return language === 'python' ? analyzePythonFile(virtualPath, sourceCode) : analyzeTypeScriptFile(virtualPath, sourceCode);
  }

  analyzeDirectory(dirPath: string): AnalysisReport {
    const startTime = Date.now();
    const files = this.discoverFiles(dirPath);
    if (files.length > this.config.maxFiles) {
      throw new Error(`Configured file limit exceeded: discovered ${files.length} analyzable files with limit ${this.config.maxFiles}.`);
    }
    const results = this.analyzeResolvedFiles(files);
    return this.buildReport(dirPath, results, startTime, files.length);
  }

  analyzeFiles(filePaths: string[], repoPath: string): AnalysisReport {
    const startTime = Date.now();
    const analyzableFiles: string[] = [];
    for (const file of filePaths.filter(f => this.walker.isAnalyzable(f))) {
      const fullPath = path.isAbsolute(file) ? file : path.join(repoPath, file);
      if (!fs.existsSync(fullPath)) continue;
      analyzableFiles.push(fullPath);
    }
    if (analyzableFiles.length > this.config.maxFiles) {
      throw new Error(`Configured file limit exceeded: discovered ${analyzableFiles.length} analyzable files with limit ${this.config.maxFiles}.`);
    }
    const results = this.analyzeResolvedFiles(analyzableFiles).map((result) => ({
      ...result,
      file: path.isAbsolute(result.file) ? path.relative(repoPath, result.file) : result.file,
      findings: result.findings.map((finding) => ({
        ...finding,
        file: path.isAbsolute(finding.file) ? path.relative(repoPath, finding.file) : finding.file,
        context: finding.context ? {
          ...finding.context,
          toolFile: finding.context.toolFile && path.isAbsolute(finding.context.toolFile)
            ? path.relative(repoPath, finding.context.toolFile)
            : finding.context.toolFile,
          callPath: finding.context.callPath?.map((nodeId) => {
            const separatorIndex = nodeId.lastIndexOf(':');
            if (separatorIndex === -1) {
              return nodeId;
            }

            const filePart = nodeId.slice(0, separatorIndex);
            const symbolPart = nodeId.slice(separatorIndex + 1);
            const relativeFile = path.isAbsolute(filePart) ? path.relative(repoPath, filePart) : filePart;
            return `${relativeFile}:${symbolPart}`;
          }),
        } : finding.context,
      })),
    }));
    return this.buildReport(repoPath, results, startTime, analyzableFiles.length);
  }

  private analyzeResolvedFiles(files: string[]): FileAnalysisResult[] {
    const unsupportedResults: FileAnalysisResult[] = [];
    const pythonInputs: Array<{ filePath: string; sourceCode: string }> = [];
    const typescriptInputs: Array<{ filePath: string; sourceCode: string }> = [];

    const total = files.length;
    const showProgress = total > 200;
    let loaded = 0;

    for (const file of files) {
      const language = this.walker.getLanguage(file);
      if (!language) {
        unsupportedResults.push({
          file,
          language: 'python',
          findings: [],
          success: false,
          error: 'Unsupported file type',
          analysisTimeMs: 0,
        });
        continue;
      }

      try {
        const sourceCode = fs.readFileSync(file, 'utf-8');
        if (language === 'python') {
          pythonInputs.push({ filePath: file, sourceCode });
        } else {
          typescriptInputs.push({ filePath: file, sourceCode });
        }
      } catch {
        unsupportedResults.push({
          file,
          language,
          findings: [],
          success: false,
          error: 'Could not read file',
          analysisTimeMs: 0,
        });
      }

      loaded++;
      if (showProgress && loaded % 100 === 0) {
        process.stderr.write(`\r  Loading files: ${loaded}/${total}...`);
      }
    }

    if (showProgress) {
      process.stderr.write(`\r  Loaded ${total} files. Building call graph...\n`);
    }

    const pythonResults = pythonInputs.length > 0 ? analyzePythonFiles(pythonInputs) : [];

    if (showProgress && typescriptInputs.length > 0) {
      process.stderr.write(`  Analyzing TypeScript/JS (${typescriptInputs.length} files)...\n`);
    }

    const typescriptResults = typescriptInputs.length > 0 ? analyzeTypeScriptFiles(typescriptInputs) : [];
    return [...pythonResults, ...typescriptResults, ...unsupportedResults];
  }

  private discoverFiles(dirPath: string): string[] {
    const files: string[] = [];
    const walkDir = (currentPath: string) => {
      for (const entry of fs.readdirSync(currentPath, { withFileTypes: true })) {
        const fullPath = path.join(currentPath, entry.name);
        const relativePath = path.relative(dirPath, fullPath);
        if (this.isExcluded(relativePath)) continue;
        if (entry.isDirectory()) walkDir(fullPath);
        else if (entry.isFile() && this.walker.isAnalyzable(fullPath)) files.push(fullPath);
      }
    };
    walkDir(dirPath);
    return files;
  }

  private isExcluded(relativePath: string): boolean {
    return this.config.exclude.some(pattern => {
      const regexPattern = pattern.replace(/\*\*/g, '{{DS}}').replace(/\*/g, '[^/]*').replace(/{{DS}}/g, '.*').replace(/\//g, '\\/');
      return new RegExp(`^${regexPattern}$`).test(relativePath.replace(/\\/g, '/'));
    });
  }

  private buildReport(repository: string, results: FileAnalysisResult[], startTime: number, totalFilesDiscovered: number): AnalysisReport {
    const failedFiles = results.filter((result) => !result.success).map((result) => result.file);
    const allCEEs = results.flatMap((result) => result.cees || []);
    const allFindings = results.flatMap(r => r.findings).filter(f => f.confidence >= this.config.minConfidence);
    const skippedFiles = results
      .filter((result) => result.skipped)
      .map((result) => ({
        file: result.file,
        language: result.language,
        reason: result.skipReason || 'File skipped.',
      }));
    const coverageDiagnostics = results
      .map((result) => result.analysisDiagnostics)
      .find((diagnostics) => diagnostics && typeof diagnostics === 'object');

    allFindings.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      const fileDiff = a.file.localeCompare(b.file);
      if (fileDiff !== 0) return fileDiff;
      return a.line - b.line;
    });
    allCEEs.sort((a, b) => {
      const fileDiff = a.file.localeCompare(b.file);
      if (fileDiff !== 0) return fileDiff;
      const lineDiff = a.line - b.line;
      if (lineDiff !== 0) return lineDiff;
      return a.tool.localeCompare(b.tool);
    });
    return {
      repository: path.basename(repository),
      filesAnalyzed: results.filter(r => r.success).map(r => r.file),
      totalFindings: allFindings.length,
      totalCEEs: allCEEs.length,
      findingsBySeverity: {
        critical: allFindings.filter(f => f.severity === Severity.CRITICAL).length,
        warning: allFindings.filter(f => f.severity === Severity.WARNING).length,
        info: allFindings.filter(f => f.severity === Severity.INFO).length,
        suppressed: allFindings.filter(f => f.severity === Severity.SUPPRESSED).length,
      },
      findings: allFindings,
      cees: allCEEs,
      metadata: {
        scannerVersion: VERSION,
        timestamp: new Date().toISOString(),
        totalTimeMs: Date.now() - startTime,
        failedFiles,
        skippedFiles,
        fileLimitHit: false,
        fileLimit: this.config.maxFiles,
        totalFilesDiscovered,
        coverageDiagnostics,
      },
    };
  }
}

export { FileLanguageRouter } from './file-language-router';
