import { Octokit } from '@octokit/rest';
import { EmitterWebhookEvent } from '@octokit/webhooks';
import simpleGit, { SimpleGit } from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AFBAnalyzer } from '../analyzer';
import { generatePRComment } from '../reporter/pr-comment';
import { WebhookContext } from '../types';

export interface GitHubAppConfig { appId: string; privateKey: string; }

async function createOctokit(config: GitHubAppConfig, installationId: number): Promise<Octokit> {
  const { createAppAuth } = await import('@octokit/auth-app');
  const auth = createAppAuth({ appId: config.appId, privateKey: config.privateKey, installationId });
  const { token } = await auth({ type: 'installation' });
  return new Octokit({ auth: token });
}

export async function handlePushEvent(payload: EmitterWebhookEvent<'push'>['payload'], config: GitHubAppConfig): Promise<void> {
  const { repository, installation, after, ref } = payload;
  if (!installation || ref.replace('refs/heads/', '') !== repository.default_branch) return;
  const context: WebhookContext = { event: 'push', owner: repository.owner.login, repo: repository.name, sha: after, branch: ref.replace('refs/heads/', ''), installationId: installation.id };
  await runAnalysis(context, config);
}

export async function handlePullRequestEvent(payload: EmitterWebhookEvent<'pull_request'>['payload'], config: GitHubAppConfig): Promise<void> {
  const { action, pull_request, repository, installation } = payload;
  if (!installation || (action !== 'opened' && action !== 'synchronize')) return;
  const octokit = await createOctokit(config, installation.id);
  const { data: files } = await octokit.pulls.listFiles({ owner: repository.owner.login, repo: repository.name, pull_number: pull_request.number });
  const context: WebhookContext = { event: 'pull_request', owner: repository.owner.login, repo: repository.name, sha: pull_request.head.sha, pullNumber: pull_request.number, branch: pull_request.head.ref, changedFiles: files.map(f => f.filename), installationId: installation.id };
  await runAnalysis(context, config);
}

async function runAnalysis(context: WebhookContext, config: GitHubAppConfig): Promise<void> {
  const octokit = await createOctokit(config, context.installationId);
  let workDir: string | null = null;
  try {
    const { data: checkRun } = await octokit.checks.create({ owner: context.owner, repo: context.repo, name: 'AFB Scanner', head_sha: context.sha, status: 'in_progress' });
    workDir = await cloneRepo(context, config);
    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = context.changedFiles ? analyzer.analyzeFiles(context.changedFiles, workDir) : analyzer.analyzeDirectory(workDir);
    report.commitSha = context.sha;
    report.pullRequest = context.pullNumber;
    const conclusion = report.findingsBySeverity.critical > 0 ? 'failure' : report.findingsBySeverity.warning > 0 ? 'neutral' : 'success';
    await octokit.checks.update({ owner: context.owner, repo: context.repo, check_run_id: checkRun.id, status: 'completed', conclusion, completed_at: new Date().toISOString(), output: { title: 'AFB Scanner', summary: `Found ${report.totalFindings} findings`, text: generatePRComment(report) } });
    if (context.pullNumber && report.totalFindings > 0) await postComment(octokit, context, report);
  } catch (error) {
    console.error('Analysis failed:', error);
  } finally {
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
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

async function postComment(octokit: Octokit, context: WebhookContext, report: any): Promise<void> {
  if (!context.pullNumber) return;
  const body = `<!-- afb-scanner -->\n${generatePRComment(report)}`;
  const { data: comments } = await octokit.issues.listComments({ owner: context.owner, repo: context.repo, issue_number: context.pullNumber });
  const existing = comments.find(c => c.body?.includes('<!-- afb-scanner -->'));
  if (existing) await octokit.issues.updateComment({ owner: context.owner, repo: context.repo, comment_id: existing.id, body });
  else await octokit.issues.createComment({ owner: context.owner, repo: context.repo, issue_number: context.pullNumber, body });
}
