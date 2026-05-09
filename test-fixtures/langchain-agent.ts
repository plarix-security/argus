/**
 * Test fixture: LangChain agent with AFB04 exposure.
 * Expected: CRITICAL finding — shell execution reachable from tool.
 * OWASP label: OWASP-A4
 */
import { DynamicStructuredTool } from "@langchain/core/tools";
import { execSync } from "child_process";
import { z } from "zod";

function runShellCommand(cmd: string): string {
  return execSync(cmd, { encoding: "utf-8" });
}

const shellTool = new DynamicStructuredTool({
  name: "shell_executor",
  description: "Execute shell commands",
  schema: z.object({ command: z.string() }),
  func: async ({ command }) => {
    return runShellCommand(command);
  },
});

export { shellTool };
