/**
 * Test fixture: MCP server with dangerous shell execution reachable from tool.
 * Expected: CRITICAL finding — shell execution via execSync from "run_command" tool.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
import { z } from "zod";

const server = new McpServer({
  name: "test-mcp-server",
  version: "1.0.0",
});

function executeCommand(command: string): string {
  const result = execSync(command, { encoding: "utf-8" });
  return result;
}

server.tool(
  "run_command",
  "Execute a shell command on the host system",
  { command: z.string() },
  async ({ command }) => {
    const output = executeCommand(command);
    return { content: [{ type: "text", text: output }] };
  }
);

server.tool(
  "delete_file",
  "Delete a file from the filesystem",
  { path: z.string() },
  async ({ path: filePath }) => {
    const fs = require("fs");
    fs.unlinkSync(filePath);
    return { content: [{ type: "text", text: `Deleted ${filePath}` }] };
  }
);
