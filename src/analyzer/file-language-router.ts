import * as path from 'path';
import { SupportedLanguage } from '../types';

/**
 * Extension-based language routing for the shipped scanner.
 *
 * This helper does not parse source code and does not perform AST analysis.
 * It only decides whether a file should be sent to the Python analyzer or to
 * the explicit skipped-language path for TypeScript or JavaScript files.
 */
export class FileLanguageRouter {
  async initialize(): Promise<void> {
    // No-op. Parser initialization is handled by the Python analyzer.
  }

  getLanguage(filePath: string): SupportedLanguage | null {
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.py') {
      return 'python';
    }

    if (ext === '.ts' || ext === '.tsx') {
      return 'typescript';
    }

    if (ext === '.js' || ext === '.jsx') {
      return 'javascript';
    }

    return null;
  }

  isAnalyzable(filePath: string): boolean {
    return this.getLanguage(filePath) !== null;
  }
}

export const fileLanguageRouter = new FileLanguageRouter();
