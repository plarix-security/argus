import { Octokit } from '@octokit/rest';
import { EmitterWebhookEvent } from '@octokit/webhooks';
import simpleGit, { SimpleGit } from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AFBAnalyzer } from '../analyzer';
import { generatePRComment } from '../reporter/pr-comment';
import { generateIssueTitle, generateIssueBody, generateNoFindingsIssue } from '../reporter/issue-formatter';
import { AnalysisReport, WebhookContext } from '../types';

export interface GitHubAppConfig {
  appId: string;
  privateKey: string;
}

interface InstallationContext {
  owner: string;
  repo: string;
  defaultBranch: string;
  installationId: number;
  commitSha: string;
}

type CheckConclusion = 'success' | 'neutral' | 'failure';

interface CheckOutput {
  title: string;
  summary: string;
  text: string;
  conclusion: CheckConclusion;
}

const CHECK_NAME = 'WyScan';
const COMMENT_MARKER = '<!-- afb-scanner -->';

async function createOctokit(config: GitHubAppConfig, installationId: number): Promise<Octokit> {
  const { createAppAuth } = await import('@octokit/auth-app');
  const auth = createAppAuth({ appId: config.appId, privateKey: config.privateKey, installationId });
  const { token } = await auth({ type: 'installation' });
  return new Octokit({ auth: token });
}

export function summarizeReportForCheck(report: AnalysisReport): CheckOutput {
  const skippedFiles = report.metadata.skippedFiles;
  const failedFiles = report.metadata.failedFiles;
  const skippedLanguages = Array.from(new Set(skippedFiles.map((file) => file.language))).sort();
  const partialCoverage = skippedFiles.length > 0 || failedFiles.length > 0;
  const noUsableCoverage = report.filesAnalyzed.length === 0 && failedFiles.length > 0;

  let title = 'Scan completed';
  let conclusion: CheckConclusion = 'success';

  if (noUsableCoverage) {
    title = 'Scan failed';
    conclusion = 'failure';
  } else if (report.findingsBySeverity.critical > 0) {
    title = 'Critical findings reported';
    conclusion = 'failure';
  } else if (partialCoverage) {
    title = report.totalFindings > 0 ? 'Findings reported with partial coverage' : 'No findings reported; coverage partial';
    conclusion = 'neutral';
  } else if (report.findingsBySeverity.warning > 0 || report.findingsBySeverity.info > 0) {
    title = 'Findings reported';
    conclusion = 'neutral';
  } else {
    title = 'No findings reported';
  }

  const summaryLines = [
    `Files analyzed: ${report.filesAnalyzed.length}`,
    `CEEs detected: ${report.totalCEEs}`,
    `Findings reported: ${report.totalFindings} (critical: ${report.findingsBySeverity.critical}, warning: ${report.findingsBySeverity.warning}, info: ${report.findingsBySeverity.info})`,
    `Coverage: ${partialCoverage ? 'partial' : 'full'}`,
  ];

  if (failedFiles.length > 0) {
    summaryLines.push(`Files failed: ${failedFiles.length}`);
  }

  if (skippedFiles.length > 0) {
    summaryLines.push(`Files skipped: ${skippedFiles.length}`);
  }

  if (skippedLanguages.length > 0) {
    summaryLines.push(`Skipped languages: ${skippedLanguages.join(', ')}`);
  }

  summaryLines.push('The analyzed Python file set is graphed together. Changed-file scans do not guarantee full repository coverage.');

  return {
    title,
    conclusion,
    summary: summaryLines.join('\n'),
    text: generatePRComment(report),
  };
}

export function buildFailedCheckOutput(error: unknown): CheckOutput {
  const detail = error instanceof Error ? error.message : String(error);

  return {
    title: 'Scan failed',
    conclusion: 'failure',
    summary: [
      'The scan did not complete.',
      `Failure: ${detail}`,
      'No clean-scan conclusion can be drawn from this run.',
    ].join('\n'),
    text: `## WyScan Report

**Scan status:** failed

The scan did not complete.

Failure: ${detail}

No clean-scan conclusion can be drawn from this run.`,
  };
}

/**
 * Ensure the "security" label exists in the repository
 * Creates it if it doesn't exist, with GitHub's red color
 */
async function ensureSecurityLabel(
  octokit: Octokit,
  owner: string,
  repo: string
): Promise<void> {
  try {
    await octokit.issues.getLabel({ owner, repo, name: 'security' });
  } catch (error: any) {
    if (error.status === 404) {
      try {
        await octokit.issues.createLabel({
          owner,
          repo,
          name: 'security',
          color: 'd73a4a',  // GitHub red
          description: 'Security vulnerability or analysis report'
        });
        console.log(`Created "security" label in ${owner}/${repo}`);
      } catch (createError) {
        console.error(`Failed to create security label: ${createError}`);
        // Continue anyway - we'll post issue without label
      }
    }
  }
}

/**
 * Post a security issue to the repository
 * Ensures the security label exists and applies it
 */
async function postSecurityIssue(
  octokit: Octokit,
  owner: string,
  repo: string,
  title: string,
  body: string
): Promise<void> {
  try {
    await ensureSecurityLabel(octokit, owner, repo);

    const { data: issue } = await octokit.issues.create({
      owner,
      repo,
      title,
      body,
      labels: ['security']
    });

    console.log(`Posted security issue to ${owner}/${repo}: ${issue.html_url}`);
  } catch (error) {
    console.error(`Failed to post issue to ${owner}/${repo}:`, error);
    // Don't throw - we don't want one repo failure to block others
  }
}

/**
 * Clone a repository for installation scan
 * Clones the default branch at HEAD
 */
async function cloneRepoForInstallation(
  context: InstallationContext,
  config: GitHubAppConfig
): Promise<string> {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-install-'));
  const { createAppAuth } = await import('@octokit/auth-app');
  const auth = createAppAuth({
    appId: config.appId,
    privateKey: config.privateKey,
    installationId: context.installationId
  });
  const { token } = await auth({ type: 'installation' });

  const git: SimpleGit = simpleGit();
  await git.clone(
    `https://x-access-token:${token}@github.com/${context.owner}/${context.repo}.git`,
    workDir,
    ['--depth', '1', '--branch', context.defaultBranch]
  );

  return workDir;
}

/**
 * Run a full repository scan and post issue with results
 */
async function runFullRepoScan(
  context: InstallationContext,
  config: GitHubAppConfig
): Promise<void> {
  const octokit = await createOctokit(config, context.installationId);
  let workDir: string | null = null;

  try {
    console.log(`Scanning ${context.owner}/${context.repo} at ${context.commitSha.slice(0, 7)}...`);

    // Clone repo
    workDir = await cloneRepoForInstallation(context, config);

    // Get actual commit SHA after clone
    const git: SimpleGit = simpleGit(workDir);
    const log = await git.log(['-1']);
    const actualSha = log.latest?.hash || context.commitSha;

    // Run analysis
    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(workDir);

    // Format issue
    const repoFullName = `${context.owner}/${context.repo}`;
    const title = generateIssueTitle(actualSha);
    const body = report.totalFindings > 0
      ? generateIssueBody(report, repoFullName, actualSha)
      : generateNoFindingsIssue(report, repoFullName, actualSha);

    // Post issue
    await postSecurityIssue(octokit, context.owner, context.repo, title, body);

  } catch (error) {
    console.error(`Scan failed for ${context.owner}/${context.repo}:`, error);
    // Post error issue
    try {
      const errorBody = `# ❌ WyScan Scan Failed\n\n` +
        `**Repository:** \`${context.owner}/${context.repo}\`\n` +
        `**Commit:** \`${context.commitSha.slice(0, 7)}\`\n\n` +
        `The security scan could not complete.\n\n` +
        `**Error:** ${error instanceof Error ? error.message : String(error)}\n\n` +
        `Please check repository access and file formats.`;

      await postSecurityIssue(
        octokit,
        context.owner,
        context.repo,
        '[Wyscan] Scan Failed',
        errorBody
      );
    } catch (postError) {
      console.error('Failed to post error issue:', postError);
    }
  } finally {
    if (workDir) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  }
}

/**
 * Handle installation.created event
 * Scans all repositories in the installation and posts issues
 */
export async function handleInstallationEvent(
  payload: EmitterWebhookEvent<'installation'>['payload'],
  config: GitHubAppConfig
): Promise<void> {
  const { installation, repositories, action } = payload;

  if (action !== 'created' || !repositories || repositories.length === 0) {
    console.log('Installation event skipped: no repositories or not created action');
    return;
  }

  console.log(`Installation created for ${repositories.length} repositories`);

  // Scan each repository
  for (const repo of repositories) {
    const context: InstallationContext = {
      owner: repo.full_name.split('/')[0],
      repo: repo.name,
      defaultBranch: repo.default_branch || 'main',
      installationId: installation.id,
      commitSha: 'HEAD', // Will resolve to actual SHA during clone
    };

    // Run scan (don't await - process repos in parallel)
    runFullRepoScan(context, config).catch(err => {
      console.error(`Failed to scan ${repo.full_name}:`, err);
    });
  }

  console.log('All installation scans initiated');
}

export async function handlePushEvent(payload: EmitterWebhookEvent<'push'>['payload'], config: GitHubAppConfig): Promise<void> {
  const { repository, installation, after, ref } = payload;

  if (!installation || ref.replace('refs/heads/', '') !== repository.default_branch) {
    return;
  }

  const context: WebhookContext = {
    event: 'push',
    owner: repository.owner.login,
    repo: repository.name,
    sha: after,
    branch: ref.replace('refs/heads/', ''),
    installationId: installation.id,
  };

  await runAnalysis(context, config);
}

export async function handlePullRequestEvent(payload: EmitterWebhookEvent<'pull_request'>['payload'], config: GitHubAppConfig): Promise<void> {
  const { action, pull_request, repository, installation } = payload;

  if (!installation || (action !== 'opened' && action !== 'synchronize')) {
    return;
  }

  const octokit = await createOctokit(config, installation.id);
  const { data: files } = await octokit.pulls.listFiles({
    owner: repository.owner.login,
    repo: repository.name,
    pull_number: pull_request.number,
  });

  const context: WebhookContext = {
    event: 'pull_request',
    owner: repository.owner.login,
    repo: repository.name,
    sha: pull_request.head.sha,
    pullNumber: pull_request.number,
    branch: pull_request.head.ref,
    changedFiles: files.map((file) => file.filename),
    installationId: installation.id,
  };

  await runAnalysis(context, config);
}

async function runAnalysis(context: WebhookContext, config: GitHubAppConfig): Promise<void> {
  const octokit = await createOctokit(config, context.installationId);
  let workDir: string | null = null;
  let checkRunId: number | null = null;

  try {
    const { data: checkRun } = await octokit.checks.create({
      owner: context.owner,
      repo: context.repo,
      name: CHECK_NAME,
      head_sha: context.sha,
      status: 'in_progress',
    });
    checkRunId = checkRun.id;

    workDir = await cloneRepo(context, config);
    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();

    const report = context.changedFiles
      ? analyzer.analyzeFiles(context.changedFiles, workDir)
      : analyzer.analyzeDirectory(workDir);

    report.commitSha = context.sha;
    report.pullRequest = context.pullNumber;

    const output = summarizeReportForCheck(report);

    await octokit.checks.update({
      owner: context.owner,
      repo: context.repo,
      check_run_id: checkRun.id,
      status: 'completed',
      conclusion: output.conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title: output.title,
        summary: output.summary,
        text: output.text,
      },
    });

    if (context.pullNumber && (report.totalFindings > 0 || report.metadata.failedFiles.length > 0 || report.metadata.skippedFiles.length > 0)) {
      await postComment(octokit, context, `${COMMENT_MARKER}\n${output.text}`);
    }
  } catch (error) {
    console.error('Analysis failed:', error);

    if (checkRunId !== null) {
      const output = buildFailedCheckOutput(error);
      await octokit.checks.update({
        owner: context.owner,
        repo: context.repo,
        check_run_id: checkRunId,
        status: 'completed',
        conclusion: output.conclusion,
        completed_at: new Date().toISOString(),
        output: {
          title: output.title,
          summary: output.summary,
          text: output.text,
        },
      });

      if (context.pullNumber) {
        await postComment(octokit, context, `${COMMENT_MARKER}\n${output.text}`);
      }
    }
  } finally {
    if (workDir) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  }
}

async function cloneRepo(context: WebhookContext, config: GitHubAppConfig): Promise<string> {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'afb-'));
  const { createAppAuth } = await import('@octokit/auth-app');
  const auth = createAppAuth({ appId: config.appId, privateKey: config.privateKey, installationId: context.installationId });
  const { token } = await auth({ type: 'installation' });
  const git: SimpleGit = simpleGit();
  await git.clone(`https://x-access-token:${token}@github.com/${context.owner}/${context.repo}.git`, workDir, ['--depth', '1', '--branch', context.branch]);
  await simpleGit(workDir).checkout(context.sha);
  return workDir;
}

async function postComment(octokit: Octokit, context: WebhookContext, body: string): Promise<void> {
  if (!context.pullNumber) {
    return;
  }

  const { data: comments } = await octokit.issues.listComments({
    owner: context.owner,
    repo: context.repo,
    issue_number: context.pullNumber,
  });
  const existing = comments.find((comment) => comment.body?.includes(COMMENT_MARKER));

  if (existing) {
    await octokit.issues.updateComment({
      owner: context.owner,
      repo: context.repo,
      comment_id: existing.id,
      body,
    });
    return;
  }

  await octokit.issues.createComment({
    owner: context.owner,
    repo: context.repo,
    issue_number: context.pullNumber,
    body,
  });
}
