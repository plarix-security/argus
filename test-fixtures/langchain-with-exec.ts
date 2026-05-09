/**
 * Test fixture: LangChain agent with shell exec and file operations.
 * Expected: CRITICAL finding for shell exec, HIGH finding for file ops.
 * OWASP label: OWASP-A4
 */
import { DynamicStructuredTool } from "@langchain/core/tools";
import { execSync } from "child_process";
import * as fs from "fs";
import { z } from "zod";

function runCommand(cmd: string): string {
  return execSync(cmd, { encoding: "utf-8" });
}

function deleteFile(filePath: string): void {
  fs.unlinkSync(filePath);
}

const shellTool = new DynamicStructuredTool({
  name: "shell_executor",
  description: "Execute shell commands on the host",
  schema: z.object({ command: z.string() }),
  func: async ({ command }) => {
    return runCommand(command);
  },
});

const fileDeleteTool = new DynamicStructuredTool({
  name: "file_deleter",
  description: "Delete files from the filesystem",
  schema: z.object({ path: z.string() }),
  func: async ({ path: filePath }) => {
    deleteFile(filePath);
    return `Deleted: ${filePath}`;
  },
});

export { shellTool, fileDeleteTool };
