/**
 * GitHub Webhook Handler
 *
 * Handles GitHub App webhooks for push and pull_request events.
 * Triggers AFB analysis and posts results as PR comments.
 */

import { Octokit } from "@octokit/rest";
import { createAppAuth } from "@octokit/auth-app";
import simpleGit, { SimpleGit } from "simple-git";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { analyzeDirectory, analyzeSpecificFiles } from "../analyzer";
import { generatePRComment, generateStatusSummary } from "../reporter/pr-comment";
import { WebhookContext, AnalysisReport } from "../types";

/**
 * GitHub App configuration.
 */
interface GitHubAppConfig {
  appId: string;
  privateKey: string;
  webhookSecret?: string;
}

/**
 * Get an authenticated Octokit instance for an installation.
 */
async function getInstallationOctokit(
  config: GitHubAppConfig,
  installationId: number
): Promise<Octokit> {
  const auth = createAppAuth({
    appId: config.appId,
    privateKey: config.privateKey,
    installationId,
  });

  const installationAuth = await auth({ type: "installation" });

  return new Octokit({
    auth: installationAuth.token,
  });
}

/**
 * Clone a repository to a temporary directory.
 */
async function cloneRepository(
  octokit: Octokit,
  owner: string,
  repo: string,
  sha: string
): Promise<string> {
  // Create temp directory
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "afb-scanner-"));

  // Get installation token for authenticated clone
  const { data: repoData } = await octokit.repos.get({ owner, repo });
  const cloneUrl = repoData.clone_url;

  // Clone the repository
  const git: SimpleGit = simpleGit();
  await git.clone(cloneUrl, tempDir, ["--depth", "1"]);

  // Checkout specific commit
  const repoGit = simpleGit(tempDir);
  await repoGit.checkout(sha);

  return tempDir;
}

/**
 * Get list of changed files in a pull request.
 */
async function getPRChangedFiles(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number
): Promise<string[]> {
  const { data: files } = await octokit.pulls.listFiles({
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });

  return files
    .filter((f) => f.status !== "removed")
    .map((f) => f.filename);
}

/**
 * Post analysis results as a PR comment.
 */
async function postPRComment(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
  report: AnalysisReport
): Promise<void> {
  const body = generatePRComment(report);

  // Check for existing AFB Scanner comment to update
  const { data: comments } = await octokit.issues.listComments({
    owner,
    repo,
    issue_number: pullNumber,
    per_page: 100,
  });

  const existingComment = comments.find((c) =>
    c.body?.includes("AFB Scanner Report")
  );

  if (existingComment) {
    // Update existing comment
    await octokit.issues.updateComment({
      owner,
      repo,
      comment_id: existingComment.id,
      body,
    });
  } else {
    // Create new comment
    await octokit.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body,
    });
  }
}

/**
 * Create a commit status check.
 */
async function createCommitStatus(
  octokit: Octokit,
  owner: string,
  repo: string,
  sha: string,
  report: AnalysisReport
): Promise<void> {
  const { totalFindings, findingsBySeverity } = report;

  // Determine status state
  let state: "success" | "failure" | "pending" = "success";
  if (findingsBySeverity.critical > 0) {
    state = "failure";
  } else if (totalFindings > 0) {
    // Still pass but with findings noted
    state = "success";
  }

  await octokit.repos.createCommitStatus({
    owner,
    repo,
    sha,
    state,
    context: "AFB Scanner",
    description: generateStatusSummary(report),
  });
}

/**
 * Clean up temporary directory.
 */
function cleanup(tempDir: string): void {
  try {
    fs.rmSync(tempDir, { recursive: true, force: true });
  } catch (error) {
    console.error(`Failed to cleanup ${tempDir}:`, error);
  }
}

/**
 * Handle a pull_request webhook event.
 */
export async function handlePullRequest(
  config: GitHubAppConfig,
  context: WebhookContext
): Promise<AnalysisReport> {
  const { owner, repo, sha, pullNumber, installationId, changedFiles } = context;

  if (!pullNumber) {
    throw new Error("Pull request number is required");
  }

  console.log(`[AFB Scanner] Analyzing PR #${pullNumber} in ${owner}/${repo}`);

  const octokit = await getInstallationOctokit(config, installationId);
  let tempDir: string | undefined;

  try {
    // Clone repository
    tempDir = await cloneRepository(octokit, owner, repo, sha);

    // Get changed files if not provided
    const filesToAnalyze = changedFiles || await getPRChangedFiles(
      octokit,
      owner,
      repo,
      pullNumber
    );

    // Filter to only analyzable files
    const analyzableFiles = filesToAnalyze.filter(
      (f) => f.endsWith(".py") || f.endsWith(".ts") || f.endsWith(".js") ||
            f.endsWith(".tsx") || f.endsWith(".jsx")
    );

    console.log(`[AFB Scanner] Analyzing ${analyzableFiles.length} files`);

    // Run analysis
    const report = analyzeSpecificFiles(tempDir, analyzableFiles, {
      minConfidence: 0.5,
    });

    // Update report with PR context
    report.repository = `${owner}/${repo}`;
    report.pullRequest = pullNumber;
    report.commitSha = sha;

    // Post results
    await postPRComment(octokit, owner, repo, pullNumber, report);
    await createCommitStatus(octokit, owner, repo, sha, report);

    console.log(`[AFB Scanner] Found ${report.totalFindings} AFB04 boundaries`);

    return report;
  } finally {
    if (tempDir) {
      cleanup(tempDir);
    }
  }
}

/**
 * Handle a push webhook event.
 */
export async function handlePush(
  config: GitHubAppConfig,
  context: WebhookContext
): Promise<AnalysisReport> {
  const { owner, repo, sha, branch, installationId } = context;

  console.log(`[AFB Scanner] Analyzing push to ${branch} in ${owner}/${repo}`);

  const octokit = await getInstallationOctokit(config, installationId);
  let tempDir: string | undefined;

  try {
    // Clone repository
    tempDir = await cloneRepository(octokit, owner, repo, sha);

    // Run full analysis
    const report = analyzeDirectory(tempDir, {
      minConfidence: 0.5,
      maxFiles: 500,
    });

    // Update report with push context
    report.repository = `${owner}/${repo}`;
    report.commitSha = sha;

    // Create commit status
    await createCommitStatus(octokit, owner, repo, sha, report);

    console.log(`[AFB Scanner] Found ${report.totalFindings} AFB04 boundaries`);

    return report;
  } finally {
    if (tempDir) {
      cleanup(tempDir);
    }
  }
}

/**
 * Parse webhook payload and extract context.
 */
export function parseWebhookPayload(
  event: string,
  payload: Record<string, unknown>
): WebhookContext | null {
  if (event === "pull_request") {
    const pr = payload.pull_request as Record<string, unknown>;
    const repo = payload.repository as Record<string, unknown>;
    const installation = payload.installation as Record<string, unknown>;

    if (!pr || !repo || !installation) {
      return null;
    }

    const head = pr.head as Record<string, unknown>;
    const base = pr.base as Record<string, unknown>;

    return {
      event: "pull_request",
      owner: (repo.owner as Record<string, unknown>).login as string,
      repo: repo.name as string,
      sha: head.sha as string,
      pullNumber: pr.number as number,
      branch: head.ref as string,
      installationId: installation.id as number,
    };
  }

  if (event === "push") {
    const repo = payload.repository as Record<string, unknown>;
    const installation = payload.installation as Record<string, unknown>;

    if (!repo || !installation) {
      return null;
    }

    return {
      event: "push",
      owner: (repo.owner as Record<string, unknown>).login as string || (repo.owner as Record<string, unknown>).name as string,
      repo: repo.name as string,
      sha: payload.after as string,
      branch: (payload.ref as string).replace("refs/heads/", ""),
      installationId: installation.id as number,
    };
  }

  return null;
}

export { GitHubAppConfig };
