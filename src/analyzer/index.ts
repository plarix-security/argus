import * as fs from 'fs';
import * as path from 'path';
import { ASTWalker, astWalker } from './ast-walker';
import { analyzePythonFile, ensureParserInitialized } from './python/detector';
import { analyzeTypeScriptFile } from './typescript/detector';
import { AFBFinding, AnalysisReport, AnalyzerConfig, FileAnalysisResult, SupportedLanguage, Severity } from '../types';

const SCANNER_VERSION = '0.6.0';
const DEFAULT_CONFIG: Required<AnalyzerConfig> = {
  include: ['**/*.py', '**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
  exclude: ['**/node_modules/**', '**/.venv/**', '**/venv/**', '**/__pycache__/**', '**/dist/**', '**/build/**', '**/.git/**', '**/test/**', '**/tests/**', '**/*.test.*', '**/*.spec.*'],
  minConfidence: 0.7,
  maxFiles: 1000,
  changedFilesOnly: false,
};

export class AFBAnalyzer {
  private walker: ASTWalker;
  private config: Required<AnalyzerConfig>;
  private initialized = false;

  constructor(config?: AnalyzerConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.walker = astWalker;
  }

  async ensureInitialized() {
    if (!this.initialized) {
      await this.walker.initialize();
      await ensureParserInitialized();
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
    const results: FileAnalysisResult[] = [];
    const failedFiles: string[] = [];
    for (const file of files.slice(0, this.config.maxFiles)) {
      const result = this.analyzeFile(file);
      results.push(result);
      if (!result.success) failedFiles.push(file);
    }
    return this.buildReport(dirPath, results, failedFiles, startTime);
  }

  analyzeFiles(filePaths: string[], repoPath: string): AnalysisReport {
    const startTime = Date.now();
    const results: FileAnalysisResult[] = [];
    const failedFiles: string[] = [];
    for (const file of filePaths.filter(f => this.walker.isAnalyzable(f))) {
      const fullPath = path.isAbsolute(file) ? file : path.join(repoPath, file);
      if (!fs.existsSync(fullPath)) continue;
      const result = this.analyzeFile(fullPath);
      result.file = file;
      results.push(result);
      if (!result.success) failedFiles.push(file);
    }
    return this.buildReport(repoPath, results, failedFiles, startTime);
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

  private buildReport(repository: string, results: FileAnalysisResult[], failedFiles: string[], startTime: number): AnalysisReport {
    const allFindings = results.flatMap(r => r.findings).filter(f => f.confidence >= this.config.minConfidence);
    allFindings.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2, suppressed: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      const fileDiff = a.file.localeCompare(b.file);
      if (fileDiff !== 0) return fileDiff;
      return a.line - b.line;
    });
    return {
      repository: path.basename(repository),
      filesAnalyzed: results.filter(r => r.success).map(r => r.file),
      totalFindings: allFindings.length,
      findingsBySeverity: {
        critical: allFindings.filter(f => f.severity === Severity.CRITICAL).length,
        warning: allFindings.filter(f => f.severity === Severity.WARNING).length,
        info: allFindings.filter(f => f.severity === Severity.INFO).length,
        suppressed: allFindings.filter(f => f.severity === Severity.SUPPRESSED).length,
      },
      findings: allFindings,
      metadata: { scannerVersion: SCANNER_VERSION, timestamp: new Date().toISOString(), totalTimeMs: Date.now() - startTime, failedFiles },
    };
  }
}

export const analyzer = new AFBAnalyzer();
export { ASTWalker } from './ast-walker';
