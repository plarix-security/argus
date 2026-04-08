/**
 * TypeScript/JavaScript Call Graph Builder
 *
 * Builds a call graph from parsed TypeScript files to trace:
 * 1. Tool registration points via semantic root extraction
 * 2. Execution paths from tools to dangerous operations
 * 3. Presence or absence of structural policy gates in call paths
 *
 * Mirrors Python call graph architecture but adapted for TypeScript/JavaScript.
 */

import {
  ParsedTypeScriptFile,
  FunctionDef,
  ClassDef,
  CallSite,
  ImportInfo,
  ControlFlowInfo,
  CallArgumentInfo,
} from './ast-parser';
import {
  TypeScriptSemanticIndex,
  extractSemanticInvocationRoots,
  SemanticInvocationRoot,
} from './semantic-index';
import { ExecutionCategory, Severity } from '../../types';
import * as path from 'path';

/**
 * Import resolution result
 */
export interface ResolvedImport {
  name: string;
  alias?: string;
  resolvedFile?: string;
  resolved: boolean;
  modulePath: string;
}

/**
 * A node in the call graph
 */
export interface CallGraphNode {
  id: string;
  name: string;
  className?: string;
  startLine: number;
  endLine: number;
  callees: Set<string>;
  callers: Set<string>;
  isToolRegistration: boolean;
  framework?: string;
  toolDetectionKind?: 'semantic' | 'heuristic';
  toolDetectionEvidence?: string;
  dangerousOps: DangerousOperation[];
  hasPolicyGate: boolean;
  hasHeuristicGateIndicator?: boolean;
  controlFlow?: ControlFlowInfo;
  sourceFile?: string;
  parameters?: string[];
  outgoingCalls: Array<{
    targetId?: string;
    call: CallSite;
  }>;
  isCrossFileResolved?: boolean;
}

/**
 * A dangerous operation detected in code
 */
export interface DangerousOperation {
  callee: string;
  category: ExecutionCategory;
  severity: Severity;
  line: number;
  column: number;
  codeSnippet: string;
  sourceFile?: string;
  enclosingNodeId?: string;
  argumentDetails?: CallArgumentInfo[];
  resourceHint?: string;
  changesState?: boolean;
  detectionKind?: 'semantic' | 'heuristic';
  detectionEvidence?: string;
  resolvedIdentity?: string;
}

/**
 * Result of call graph analysis
 */
export interface CallGraphAnalysis {
  nodes: Map<string, CallGraphNode>;
  toolRegistrations: CallGraphNode[];
  exposedPaths: ExposedPath[];
}

/**
 * An exposed execution path from tool to dangerous operation
 */
export interface ExposedPath {
  tool: CallGraphNode;
  operation: DangerousOperation;
  path: string[];
  hasGate: boolean;
  involvesCrossFile: boolean;
  unresolvedCalls: string[];
  depthLimitHit: boolean;
  inputFlowsToOperation: boolean;
  supportingEvidence: string[];
}

/**
 * Import resolution configuration
 */
export interface ImportResolutionConfig {
  searchPaths: string[];
  fileExtensions: string[];
  packageJsonLookup: boolean;
}

export const DEFAULT_IMPORT_CONFIG: ImportResolutionConfig = {
  searchPaths: ['src', 'lib', '.'],
  fileExtensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'],
  packageJsonLookup: true,
};

/**
 * Dangerous operation patterns for Node.js/TypeScript
 *
 * These are semantic patterns that match qualified module names.
 * Example: child_process.exec, fs.unlink, eval
 */
interface DangerousOperationPattern {
  identity: RegExp;
  category: ExecutionCategory;
  severity: Severity;
  description: string;
  resourceHint?: string;
  changesState?: boolean;
}

const SEMANTIC_DANGEROUS_OPERATION_PATTERNS: DangerousOperationPattern[] = [
  // ============================================
  // SHELL/PROCESS EXECUTION (CRITICAL)
  // ============================================
  { identity: /^child_process\.(exec|execSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell command execution', resourceHint: 'shell', changesState: true },
  { identity: /^child_process\.(spawn|spawnSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process spawn', resourceHint: 'process', changesState: true },
  { identity: /^child_process\.(execFile|execFileSync)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'File execution', resourceHint: 'file', changesState: true },
  { identity: /^child_process\.fork$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process fork', resourceHint: 'process', changesState: true },
  { identity: /^Bun\.(spawn|spawnSync|shell|write|file)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Bun process/shell execution', resourceHint: 'process', changesState: true },
  { identity: /^Deno\.(run|Command|create|execPath)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Deno process execution', resourceHint: 'process', changesState: true },
  { identity: /^execa(\.(command|commandSync|node|sync))?$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell execution via execa', resourceHint: 'shell', changesState: true },
  { identity: /^shelljs\.(exec|cd|rm|mv|cp|mkdir|chmod|cat|sed|grep|which|echo|pushd|popd|dirs|ln|exit|env|sort|tail|uniq|head|touch)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell operation via shelljs', resourceHint: 'shell', changesState: true },
  { identity: /^\$`.*`$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell execution via zx', resourceHint: 'shell', changesState: true },

  // ============================================
  // CODE EXECUTION (CRITICAL)
  // ============================================
  { identity: /^eval$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'JavaScript eval', changesState: true },
  { identity: /^Function$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic function creation via Function constructor', changesState: true },
  { identity: /^vm\.(runInContext|runInNewContext|runInThisContext|compileFunction)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'VM code execution', changesState: true },
  { identity: /^vm\.Script$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'VM script compilation', changesState: true },
  { identity: /^require$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic module require', changesState: true },
  { identity: /^import$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Dynamic import', changesState: true },
  { identity: /^setTimeout$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.WARNING, description: 'Potentially dynamic code via setTimeout', changesState: true },
  { identity: /^setInterval$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.WARNING, description: 'Potentially dynamic code via setInterval', changesState: true },

  // ============================================
  // FILE DELETION (CRITICAL)
  // ============================================
  { identity: /^fs\.(unlink|unlinkSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(rm|rmSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File/directory deletion', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(rmdir|rmdirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Directory deletion', resourceHint: 'directory', changesState: true },
  { identity: /^fs\/promises\.(unlink|rm|rmdir)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Async file deletion', resourceHint: 'file', changesState: true },
  { identity: /^fse?\.(remove|removeSync|emptyDir|emptyDirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion via fs-extra', resourceHint: 'file', changesState: true },
  { identity: /^rimraf(\.sync)?$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'Recursive deletion via rimraf', resourceHint: 'directory', changesState: true },
  { identity: /^del(\.sync)?$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion via del', resourceHint: 'file', changesState: true },

  // ============================================
  // FILE WRITE (WARNING)
  // ============================================
  { identity: /^fs\.(writeFile|writeFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(appendFile|appendFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File append', resourceHint: 'file', changesState: true },
  { identity: /^fs\.createWriteStream$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Write stream creation', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(mkdir|mkdirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Directory creation', resourceHint: 'directory', changesState: true },
  { identity: /^fs\.(rename|renameSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File rename', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(copyFile|copyFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File copy', resourceHint: 'file', changesState: true },
  { identity: /^fs\.(chmod|chmodSync|chown|chownSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File permission change', resourceHint: 'file', changesState: true },
  { identity: /^fs\/promises\.(writeFile|appendFile|mkdir|rename|copyFile|chmod|chown)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Async file write operation', resourceHint: 'file', changesState: true },
  { identity: /^fse?\.(writeFile|writeFileSync|outputFile|outputFileSync|copy|copySync|move|moveSync|ensureDir|ensureDirSync|mkdirp|mkdirpSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write via fs-extra', resourceHint: 'file', changesState: true },

  // ============================================
  // HTTP MUTATIONS (WARNING)
  // ============================================
  { identity: /^fetch$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via fetch', resourceHint: 'http', changesState: false },
  { identity: /^axios(\.(post|put|patch|delete|request))?$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via axios', resourceHint: 'http', changesState: true },
  { identity: /^got(\.(post|put|patch|delete))?$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via got', resourceHint: 'http', changesState: true },
  { identity: /^superagent\.(post|put|patch|delete|del)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via superagent', resourceHint: 'http', changesState: true },
  { identity: /^node-fetch$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via node-fetch', resourceHint: 'http', changesState: false },
  { identity: /^undici\.(fetch|request)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request via undici', resourceHint: 'http', changesState: false },
  { identity: /^request(\.(post|put|patch|delete|del))?$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation via request', resourceHint: 'http', changesState: true },

  // ============================================
  // ORM/DATABASE - Prisma (WARNING/CRITICAL)
  // ============================================
  { identity: /^prisma\.\w+\.(create|createMany|update|updateMany|upsert|delete|deleteMany)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Prisma database mutation', changesState: true },
  { identity: /^prisma\.\$executeRaw(Unsafe)?$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Prisma raw SQL execution', changesState: true },
  { identity: /^prisma\.\$queryRaw(Unsafe)?$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Prisma raw SQL query', changesState: false },
  { identity: /^prisma\.\w+\.findMany$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Prisma database read', changesState: false },
  { identity: /^prisma\.\w+\.findUnique$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Prisma database read', changesState: false },
  { identity: /^prisma\.\w+\.findFirst$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Prisma database read', changesState: false },

  // ============================================
  // ORM/DATABASE - TypeORM (WARNING/CRITICAL)
  // ============================================
  { identity: /^(repository|entityManager|connection)\.(save|insert|update|delete|remove|softRemove|recover)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'TypeORM database mutation', changesState: true },
  { identity: /^(repository|entityManager|connection|queryRunner)\.query$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'TypeORM raw query execution', changesState: true },
  { identity: /^queryBuilder\.(insert|update|delete)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'TypeORM query builder mutation', changesState: true },
  { identity: /^(repository|entityManager)\.(find|findOne|findBy|findOneBy)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'TypeORM database read', changesState: false },

  // ============================================
  // ORM/DATABASE - Sequelize (WARNING/CRITICAL)
  // ============================================
  { identity: /^sequelize\.query$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Sequelize raw query execution', changesState: true },
  { identity: /^\w+\.(create|bulkCreate|update|destroy|upsert)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Sequelize model mutation', changesState: true },
  { identity: /^\w+\.(findAll|findOne|findByPk|findOrCreate|count)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Sequelize model read', changesState: false },

  // ============================================
  // ORM/DATABASE - Knex (WARNING/CRITICAL)
  // ============================================
  { identity: /^knex\.raw$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Knex raw SQL execution', changesState: true },
  { identity: /^knex(\.\w+)?\.(insert|update|delete|del|truncate)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Knex database mutation', changesState: true },
  { identity: /^knex(\.\w+)?\.(select|first|pluck|count)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Knex database read', changesState: false },

  // ============================================
  // ORM/DATABASE - Drizzle (WARNING/CRITICAL)
  // ============================================
  { identity: /^db\.(insert|update|delete)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Drizzle database mutation', changesState: true },
  { identity: /^db\.execute$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Drizzle raw SQL execution', changesState: true },
  { identity: /^db\.(select|query)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Drizzle database read', changesState: false },

  // ============================================
  // DATABASE - Generic SQL (WARNING/CRITICAL) - More specific patterns
  // ============================================
  { identity: /^(pool|client|connection|db|sqlite|mysql|pg|postgres)\.(query|exec|execute|run)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database query execution', changesState: true },
  { identity: /^(pool|client|connection|db)\.(begin|commit|rollback)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database transaction control', changesState: true },
  { identity: /^cursor\.(execute|executemany|executescript)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'SQLite cursor execution', changesState: true },
  { identity: /^better-sqlite3\.Database\.(exec|run|prepare)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'SQLite operation via better-sqlite3', changesState: true },
  { identity: /^better-sqlite3\.(exec|run|prepare)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'SQLite operation via better-sqlite3', changesState: true },

  // ============================================
  // REDIS (WARNING/CRITICAL)
  // ============================================
  { identity: /^(redis|redisClient|ioredis)\.(flushall|flushdb)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Redis flush operation', changesState: true },
  { identity: /^(redis|redisClient|ioredis)\.(set|hset|lpush|rpush|sadd|zadd|del|hdel|expire|setex|psetex|incr|decr|append)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Redis write operation', changesState: true },
  { identity: /^(redis|redisClient|ioredis)\.(get|hget|hgetall|lrange|smembers|zrange|keys|exists|type|ttl)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'Redis read operation', changesState: false },

  // ============================================
  // MONGODB (WARNING)
  // ============================================
  { identity: /^(collection|db)\.(insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|replaceOne|bulkWrite|drop)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'MongoDB mutation operation', changesState: true },
  { identity: /^(collection|db)\.(findOne|find|aggregate|countDocuments|distinct)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.INFO, description: 'MongoDB read operation', changesState: false },

  // ============================================
  // EMAIL (WARNING)
  // ============================================
  { identity: /^(transporter|mailer|nodemailer|nodemailer\.Transporter)\.(sendMail|send)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send via nodemailer', resourceHint: 'email', changesState: true },
  { identity: /^sgMail\.(send|sendMultiple)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send via SendGrid', resourceHint: 'email', changesState: true },
  { identity: /^mailgun\.(messages\(\)\.send|messages\.create)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send via Mailgun', resourceHint: 'email', changesState: true },
  { identity: /^ses\.(sendEmail|sendRawEmail|sendTemplatedEmail)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send via AWS SES', resourceHint: 'email', changesState: true },

  // ============================================
  // AWS SDK v3 (WARNING/CRITICAL)
  // ============================================
  { identity: /^s3Client\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS S3 operation', resourceHint: 'aws-s3', changesState: true },
  { identity: /^lambdaClient\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS Lambda invocation', resourceHint: 'aws-lambda', changesState: true },
  { identity: /^snsClient\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS SNS operation', resourceHint: 'aws-sns', changesState: true },
  { identity: /^sqsClient\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS SQS operation', resourceHint: 'aws-sqs', changesState: true },
  { identity: /^dynamoDBClient\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS DynamoDB operation', resourceHint: 'aws-dynamodb', changesState: true },
  { identity: /^@aws-sdk\/.*\.send$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'AWS SDK operation', resourceHint: 'aws', changesState: true },

  // ============================================
  // BROWSER AUTOMATION - Playwright (WARNING/CRITICAL)
  // ============================================
  { identity: /^page\.evaluate$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Browser code execution via Playwright', changesState: true },
  { identity: /^page\.evaluateHandle$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Browser code execution via Playwright', changesState: true },
  { identity: /^page\.addScriptTag$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Script injection via Playwright', changesState: true },
  { identity: /^page\.goto$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Browser navigation via Playwright', resourceHint: 'http', changesState: true },
  { identity: /^page\.fill$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Form filling via Playwright', changesState: true },
  { identity: /^page\.type$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Keyboard input via Playwright', changesState: true },
  { identity: /^page\.click$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Element click via Playwright', changesState: true },
  { identity: /^page\.screenshot$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'Screenshot capture via Playwright', resourceHint: 'file', changesState: true },
  { identity: /^page\.content$/i, category: ExecutionCategory.API_CALL, severity: Severity.INFO, description: 'Page content extraction via Playwright', changesState: false },
  { identity: /^page\.(setContent|setExtraHTTPHeaders)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Page configuration via Playwright', changesState: true },

  // ============================================
  // BROWSER AUTOMATION - Puppeteer (WARNING/CRITICAL)
  // ============================================
  { identity: /^page\.evaluateOnNewDocument$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Browser code injection via Puppeteer', changesState: true },

  // ============================================
  // MESSAGE QUEUES (WARNING)
  // ============================================
  { identity: /^(queue|bullmq|bull)\.(add|addBulk|process)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Message queue operation via BullMQ', changesState: true },
  { identity: /^channel\.(sendToQueue|publish|assertQueue|assertExchange)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Message queue operation via amqplib', changesState: true },

  // ============================================
  // FILE READ (INFO)
  // ============================================
  { identity: /^fs\.(readFile|readFileSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read', resourceHint: 'file', changesState: false },
  { identity: /^fs\.createReadStream$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Read stream creation', resourceHint: 'file', changesState: false },
  { identity: /^fs\.(readdir|readdirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Directory listing', resourceHint: 'directory', changesState: false },
  { identity: /^fs\.(stat|statSync|lstat|lstatSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File stat', resourceHint: 'file', changesState: false },
  { identity: /^fs\.(access|accessSync|exists|existsSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File access check', resourceHint: 'file', changesState: false },
  { identity: /^fs\/promises\.(readFile|readdir|stat|lstat|access)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Async file read', resourceHint: 'file', changesState: false },
  { identity: /^fse?\.(readFile|readFileSync|readdir|readdirSync|stat|statSync|pathExists|pathExistsSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read via fs-extra', resourceHint: 'file', changesState: false },
  { identity: /^glob(\.sync)?$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'Glob file matching', resourceHint: 'file', changesState: false },
];

/**
 * Pattern-based fallback for dangerous operations
 * Used when semantic resolution fails
 */
const DANGEROUS_OPERATION_PATTERNS: DangerousOperationPattern[] = [
  // Process/Shell (CRITICAL)
  { identity: /^(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Process execution', changesState: true },
  { identity: /^(execa|shelljs|zx)$/i, category: ExecutionCategory.SHELL_EXECUTION, severity: Severity.CRITICAL, description: 'Shell execution library', changesState: true },

  // Code execution (CRITICAL)
  { identity: /^(eval|Function)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Code execution', changesState: true },
  { identity: /^(runInContext|runInNewContext|runInThisContext|compileFunction)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'VM code execution', changesState: true },
  { identity: /^(evaluate|evaluateHandle|evaluateOnNewDocument|addScriptTag)$/i, category: ExecutionCategory.CODE_EXECUTION, severity: Severity.CRITICAL, description: 'Browser code execution', changesState: true },

  // File operations (CRITICAL/WARNING)
  { identity: /^(unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|remove|removeSync|rimraf|del)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.CRITICAL, description: 'File deletion', changesState: true },
  { identity: /^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|outputFile)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.WARNING, description: 'File write', changesState: true },
  { identity: /^(readFile|readFileSync|createReadStream|readdir|readdirSync)$/i, category: ExecutionCategory.FILE_OPERATION, severity: Severity.INFO, description: 'File read', changesState: false },

  // Database (WARNING/CRITICAL)
  { identity: /^(query|execute|exec|run|prepare)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database operation', changesState: true },
  { identity: /^(insert|update|delete|destroy|upsert|bulkCreate|deleteMany|updateMany|insertMany)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.WARNING, description: 'Database mutation', changesState: true },
  { identity: /^(executeRaw|executeRawUnsafe|queryRaw|queryRawUnsafe)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Raw SQL execution', changesState: true },
  { identity: /^(flushall|flushdb)$/i, category: ExecutionCategory.DATABASE_OPERATION, severity: Severity.CRITICAL, description: 'Database flush', changesState: true },

  // HTTP (WARNING)
  { identity: /^(fetch|axios|got|request|superagent)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP request', changesState: false },
  { identity: /^(post|put|patch|delete|del)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'HTTP mutation method', changesState: true },

  // Email (WARNING)
  { identity: /^(sendMail|send|sendMultiple)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Email send', changesState: true },

  // Browser automation (WARNING)
  { identity: /^(goto|fill|type|click|screenshot)$/i, category: ExecutionCategory.API_CALL, severity: Severity.WARNING, description: 'Browser automation', changesState: true },
];

/**
 * Factory constructor to return type mappings
 * Maps constructor/factory calls to their return type for method resolution
 */
const CONSTRUCTOR_TYPE_MAPPINGS: Record<string, string> = {
  // SQLite
  'Database': 'better-sqlite3.Database',
  'better-sqlite3': 'better-sqlite3.Database',
  'sqlite3.Database': 'sqlite3.Database',
  // PostgreSQL
  'Pool': 'pg.Pool',
  'Client': 'pg.Client',
  'pg.Pool': 'pg.Pool',
  'pg.Client': 'pg.Client',
  // MySQL
  'mysql.createConnection': 'mysql.Connection',
  'mysql.createPool': 'mysql.Pool',
  'mysql2.createConnection': 'mysql2.Connection',
  // Redis
  'createClient': 'redis.RedisClient',
  'Redis': 'ioredis.Redis',
  'ioredis.Redis': 'ioredis.Redis',
  // MongoDB
  'MongoClient': 'mongodb.MongoClient',
  // Email
  'createTransport': 'nodemailer.Transporter',
  'nodemailer.createTransport': 'nodemailer.Transporter',
  // OpenAI
  'OpenAI': 'openai.OpenAI',
};

/**
 * Determine if function is a structural policy gate
 */
function isStructuralPolicyGate(func: FunctionDef): boolean {
  if (!func.controlFlow) return false;

  const cf = func.controlFlow;

  // Must have conditional execution control
  if (!cf.hasConditionalRaise && !cf.hasConditionalReturn) {
    return false;
  }

  // Must check input parameters
  if (!cf.checksParameters) {
    return false;
  }

  // Must raise authorization-related exceptions
  // NOTE: Generic 'Error' is intentionally NOT included - too broad
  const authExceptions = [
    'PermissionError',
    'UnauthorizedError',
    'ForbiddenError',
    'AuthorizationError',
    'AccessDeniedError',
    'NotAllowedError',
    'HttpException',      // NestJS
    'UnauthorizedException', // NestJS
    'ForbiddenException', // NestJS
    'BadRequestException', // NestJS
    'NotAuthorizedException', // AWS
    'PermissionDenied',
    'AccessDenied',
    'AuthError',
    'AuthenticationError',
    'InvalidCredentialsError',
  ];
  const hasAuthException = cf.raiseTypes.some(t => authExceptions.some(ae => t.includes(ae)));

  return hasAuthException;
}

/**
 * Build a map of variable names to their inferred types from constructor calls
 * Uses AST call data instead of regex pattern matching
 * e.g., const db = new Database(...) => { db: 'better-sqlite3.Database' }
 */
function buildVariableTypeMap(
  parsed: ParsedTypeScriptFile,
  imports: ImportInfo[]
): Map<string, string> {
  const typeMap = new Map<string, string>();

  // Build a map of call sites by their line number and position
  // This helps us match calls to assignments
  const callsByLine = new Map<number, CallSite[]>();
  for (const call of parsed.calls) {
    if (!callsByLine.has(call.line)) {
      callsByLine.set(call.line, []);
    }
    callsByLine.get(call.line)!.push(call);
  }

  for (const assignment of parsed.assignments) {
    // Get calls on the same line as this assignment
    const lineCalls = callsByLine.get(assignment.line) || [];

    // Strategy 1: new Constructor(...) calls
    for (const call of lineCalls) {
      // Check if it's a 'new' expression (constructor call)
      const isConstructor = call.callee.startsWith('new ') || call.memberChain.length === 1;

      if (isConstructor && call.memberChain.length > 0) {
        const constructorName = call.memberChain[0].replace(/^new\s+/, '');

        // Check if constructor is imported
        const importInfo = imports.find(imp =>
          imp.names.includes(constructorName) || imp.alias === constructorName
        );

        // Try to resolve the type
        let resolvedType: string | undefined;

        if (importInfo) {
          // Use module-qualified constructor name
          const qualifiedName = `${importInfo.module}.${constructorName}`;
          resolvedType = CONSTRUCTOR_TYPE_MAPPINGS[qualifiedName] || CONSTRUCTOR_TYPE_MAPPINGS[constructorName];
        } else {
          // Try direct constructor name
          resolvedType = CONSTRUCTOR_TYPE_MAPPINGS[constructorName];
        }

        if (resolvedType) {
          typeMap.set(assignment.target, resolvedType);
          break; // Found the constructor for this assignment
        }
      }
    }

    // Strategy 2: Factory function calls like createTransport(...), createClient(...)
    for (const call of lineCalls) {
      if (call.memberChain.length === 1) {
        // Direct function call: createTransport(...)
        const factoryName = call.memberChain[0];
        const resolvedType = CONSTRUCTOR_TYPE_MAPPINGS[factoryName];
        if (resolvedType) {
          typeMap.set(assignment.target, resolvedType);
          break;
        }
      } else if (call.memberChain.length === 2) {
        // Chained factory call: nodemailer.createTransport(...)
        const qualifiedName = call.memberChain.join('.');
        const resolvedType = CONSTRUCTOR_TYPE_MAPPINGS[qualifiedName];
        if (resolvedType) {
          typeMap.set(assignment.target, resolvedType);
          break;
        }
      }
    }
  }

  return typeMap;
}

/**
 * Resolve call identity from imports, semantic resolution, and variable type inference
 */
function resolveCallIdentity(
  call: CallSite,
  imports: ImportInfo[],
  files: Map<string, ParsedTypeScriptFile>,
  currentFile: string,
  config: ImportResolutionConfig,
  variableTypeMap?: Map<string, string>
): string | null {
  // For member expressions like db.exec, client.sendMail
  if (call.memberChain.length > 1) {
    const base = call.memberChain[0];
    const method = call.memberChain[call.memberChain.length - 1];

    // First check if base variable has a known type from constructor
    if (variableTypeMap?.has(base)) {
      const baseType = variableTypeMap.get(base)!;
      return `${baseType}.${method}`;
    }

    // Check if base is an imported module
    const importInfo = imports.find(imp =>
      imp.names.includes(base) || imp.alias === base
    );

    if (importInfo) {
      return `${importInfo.module}.${method}`;
    }

    // Return as-is for semantic matching
    return call.memberChain.join('.');
  }

  // Simple identifier - check imports
  const callee = call.callee;
  const importInfo = imports.find(imp =>
    imp.names.includes(callee) || imp.alias === callee
  );

  if (importInfo) {
    return `${importInfo.module}.${callee}`;
  }

  return null;
}

/**
 * Match dangerous operation
 */
function matchDangerousOperation(
  call: CallSite,
  resolvedIdentity: string | null,
  sourceFile: string
): DangerousOperation | null {
  // Try semantic resolution first
  if (resolvedIdentity) {
    for (const pattern of SEMANTIC_DANGEROUS_OPERATION_PATTERNS) {
      if (pattern.identity.test(resolvedIdentity)) {
        return {
          callee: resolvedIdentity,
          category: pattern.category,
          severity: pattern.severity,
          line: call.line,
          column: call.column,
          codeSnippet: call.callee,
          sourceFile,
          argumentDetails: call.argumentDetails,
          resourceHint: pattern.resourceHint,
          changesState: pattern.changesState,
          detectionKind: 'semantic',
          detectionEvidence: `Resolved module identity: ${resolvedIdentity}`,
          resolvedIdentity,
        };
      }
    }
  }

  // Fallback to pattern matching on callee name
  for (const pattern of DANGEROUS_OPERATION_PATTERNS) {
    if (pattern.identity.test(call.callee)) {
      return {
        callee: call.callee,
        category: pattern.category,
        severity: pattern.severity,
        line: call.line,
        column: call.column,
        codeSnippet: call.callee,
        sourceFile,
        argumentDetails: call.argumentDetails,
        resourceHint: pattern.resourceHint,
        changesState: pattern.changesState,
        detectionKind: 'heuristic',
        detectionEvidence: `Pattern match on callee name`,
      };
    }
  }

  return null;
}

/**
 * Resolve module path to file
 * Checks file existence against available files map
 */
function resolveModulePath(
  modulePath: string,
  currentFile: string,
  config: ImportResolutionConfig,
  availableFiles?: Set<string>
): string | null {
  const currentDir = path.dirname(currentFile);

  // Relative import
  if (modulePath.startsWith('./') || modulePath.startsWith('../')) {
    const basePath = path.resolve(currentDir, modulePath);

    // Try with extensions
    for (const ext of config.fileExtensions) {
      const candidate = basePath + ext;
      // Check if file exists in available files set
      if (availableFiles) {
        if (availableFiles.has(candidate)) {
          return candidate;
        }
      } else {
        // Fallback: return first candidate (legacy behavior for single-file analysis)
        return candidate;
      }
    }

    // Try index file
    for (const ext of config.fileExtensions) {
      const candidate = path.join(basePath, 'index' + ext);
      if (availableFiles) {
        if (availableFiles.has(candidate)) {
          return candidate;
        }
      } else {
        return candidate;
      }
    }

    // If no availableFiles provided, fall back to returning something
    if (!availableFiles) {
      return basePath + config.fileExtensions[0];
    }
  }

  // Absolute or package import - would need node_modules resolution
  // For now, return null (unresolved)
  return null;
}

/**
 * Build call graph from parsed files
 */
export function buildCallGraph(
  files: Map<string, ParsedTypeScriptFile>,
  semanticRoots?: Map<string, SemanticInvocationRoot>,
  config: ImportResolutionConfig = DEFAULT_IMPORT_CONFIG
): CallGraphAnalysis {
  const nodes = new Map<string, CallGraphNode>();
  const toolRegistrations: CallGraphNode[] = [];

  // Extract semantic roots if not provided
  if (!semanticRoots) {
    semanticRoots = extractSemanticInvocationRoots(files);
  }

  // Build nodes
  for (const [filePath, parsed] of files) {
    // Build variable type map for this file (for constructor/factory call tracking)
    const variableTypeMap = buildVariableTypeMap(parsed, parsed.imports);

    // Process functions
    for (const func of parsed.functions) {
      const nodeId = func.className
        ? `${filePath}:${func.className}.${func.name}`
        : `${filePath}:${func.name}`;

      // Check if this is a tool registration
      const semanticRoot = semanticRoots.get(nodeId);
      const isToolRegistration = !!semanticRoot;

      // Find dangerous operations in this function
      const dangerousOps: DangerousOperation[] = [];
      const outgoingCalls: Array<{ targetId?: string; call: CallSite }> = [];

      for (const call of parsed.calls) {
        if (call.enclosingFunction === func.name ||
            (func.className && call.enclosingClass === func.className && call.enclosingFunction === func.name)) {

          // Try to resolve call identity (now with variable type map)
          const resolvedIdentity = resolveCallIdentity(call, parsed.imports, files, filePath, config, variableTypeMap);

          // Check if dangerous
          const dangerousOp = matchDangerousOperation(call, resolvedIdentity, filePath);
          if (dangerousOp) {
            dangerousOp.enclosingNodeId = nodeId;
            dangerousOps.push(dangerousOp);
          }

          // Track outgoing call
          const targetId = call.enclosingClass
            ? `${filePath}:${call.enclosingClass}.${call.callee}`
            : `${filePath}:${call.callee}`;

          outgoingCalls.push({
            targetId: nodes.has(targetId) ? targetId : undefined,
            call,
          });
        }
      }

      // Check if structural policy gate
      const hasPolicyGate = isStructuralPolicyGate(func);

      const node: CallGraphNode = {
        id: nodeId,
        name: func.name,
        className: func.className,
        startLine: func.startLine,
        endLine: func.endLine,
        callees: new Set(),
        callers: new Set(),
        isToolRegistration,
        framework: semanticRoot?.framework,
        toolDetectionKind: semanticRoot ? 'semantic' : undefined,
        toolDetectionEvidence: semanticRoot?.evidence,
        dangerousOps,
        hasPolicyGate,
        controlFlow: func.controlFlow,
        sourceFile: filePath,
        parameters: func.parameters,
        outgoingCalls,
      };

      nodes.set(nodeId, node);

      if (isToolRegistration) {
        toolRegistrations.push(node);
      }
    }
  }

  // Build edges
  for (const node of nodes.values()) {
    for (const outgoing of node.outgoingCalls) {
      if (outgoing.targetId && nodes.has(outgoing.targetId)) {
        node.callees.add(outgoing.targetId);
        nodes.get(outgoing.targetId)!.callers.add(node.id);
      }
    }
  }

  // Find exposed paths
  const exposedPaths = findExposedPaths(nodes, toolRegistrations, files);

  return {
    nodes,
    toolRegistrations,
    exposedPaths,
  };
}

/**
 * Find exposed paths from tools to dangerous operations
 */
function findExposedPaths(
  nodes: Map<string, CallGraphNode>,
  toolRegistrations: CallGraphNode[],
  files: Map<string, ParsedTypeScriptFile>
): ExposedPath[] {
  const exposedPaths: ExposedPath[] = [];

  for (const tool of toolRegistrations) {
    const paths = findDangerousPathsFromNode(tool, nodes, 10);

    for (const pathInfo of paths) {
      const hasGate = pathInfo.path.some(nodeId => {
        const node = nodes.get(nodeId);
        return node?.hasPolicyGate || false;
      });

      exposedPaths.push({
        tool,
        operation: pathInfo.operation,
        path: pathInfo.path,
        hasGate,
        involvesCrossFile: pathInfo.involvesCrossFile,
        unresolvedCalls: pathInfo.unresolvedCalls,
        depthLimitHit: pathInfo.depthLimitHit,
        inputFlowsToOperation: pathInfo.inputFlowsToOperation,
        supportingEvidence: pathInfo.supportingEvidence,
      });
    }
  }

  return exposedPaths;
}

/**
 * Find paths from a node to dangerous operations (BFS)
 */
function findDangerousPathsFromNode(
  startNode: CallGraphNode,
  nodes: Map<string, CallGraphNode>,
  maxDepth: number
): Array<{
  operation: DangerousOperation;
  path: string[];
  involvesCrossFile: boolean;
  unresolvedCalls: string[];
  depthLimitHit: boolean;
  inputFlowsToOperation: boolean;
  supportingEvidence: string[];
}> {
  const results: Array<{
    operation: DangerousOperation;
    path: string[];
    involvesCrossFile: boolean;
    unresolvedCalls: string[];
    depthLimitHit: boolean;
    inputFlowsToOperation: boolean;
    supportingEvidence: string[];
  }> = [];

  const queue: Array<{ nodeId: string; path: string[]; depth: number }> = [
    { nodeId: startNode.id, path: [startNode.id], depth: 0 }
  ];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift()!;
    const node = nodes.get(current.nodeId);

    if (!node || visited.has(current.nodeId)) continue;
    visited.add(current.nodeId);

    // Check for dangerous operations in this node
    for (const op of node.dangerousOps) {
      const involvesCrossFile = current.path.some(id => {
        const n = nodes.get(id);
        return n?.sourceFile !== startNode.sourceFile;
      });

      results.push({
        operation: op,
        path: current.path,
        involvesCrossFile,
        unresolvedCalls: [],
        depthLimitHit: current.depth >= maxDepth,
        inputFlowsToOperation: false, // Would need taint analysis
        supportingEvidence: [],
      });
    }

    // Explore callees if not at depth limit
    if (current.depth < maxDepth) {
      for (const calleeId of node.callees) {
        if (!visited.has(calleeId)) {
          queue.push({
            nodeId: calleeId,
            path: [...current.path, calleeId],
            depth: current.depth + 1,
          });
        }
      }
    }
  }

  return results;
}
