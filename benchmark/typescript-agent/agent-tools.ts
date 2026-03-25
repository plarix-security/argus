/**
 * Sample LangChain.js Agent Tools
 * This file demonstrates AFB04 execution points that the scanner should detect.
 */

import { tool, DynamicTool } from "@langchain/core/tools";
import { exec, spawn } from "child_process";
import * as fs from "fs";
import axios from "axios";
import { z } from "zod";

// AFB04: Tool definition with shell execution inside
const shellTool = tool(
  async (input: { command: string }) => {
    // CRITICAL: Shell execution inside tool definition
    return new Promise((resolve, reject) => {
      exec(input.command, (error, stdout, stderr) => {
        if (error) reject(error);
        resolve(stdout);
      });
    });
  },
  {
    name: "shell_execute",
    description: "Execute a shell command",
    schema: z.object({
      command: z.string().describe("The command to execute"),
    }),
  }
);

// AFB04: Tool definition with file operations
const fileWriteTool = tool(
  async (input: { path: string; content: string }) => {
    // HIGH: File write operation inside tool definition
    fs.writeFileSync(input.path, input.content);
    return `Wrote ${input.content.length} bytes to ${input.path}`;
  },
  {
    name: "file_write",
    description: "Write content to a file",
    schema: z.object({
      path: z.string(),
      content: z.string(),
    }),
  }
);

// AFB04: DynamicTool with API calls
const apiTool = new DynamicTool({
  name: "fetch_api",
  description: "Make HTTP requests to external APIs",
  func: async (url: string) => {
    // HIGH: External API call inside tool definition
    const response = await fetch(url);
    return await response.text();
  },
});

// AFB04: Tool with axios
const axiosTool = new DynamicTool({
  name: "post_data",
  description: "POST data to an API endpoint", 
  func: async (input: string) => {
    const { url, data } = JSON.parse(input);
    // HIGH: HTTP POST request
    const response = await axios.post(url, data);
    return JSON.stringify(response.data);
  },
});

// AFB04: Code execution
const evalTool = tool(
  async (input: { expression: string }) => {
    // CRITICAL: Dynamic code execution inside tool definition
    return String(eval(input.expression));
  },
  {
    name: "evaluate",
    description: "Evaluate a JavaScript expression",
    schema: z.object({
      expression: z.string(),
    }),
  }
);

// Regular function (not a tool) - lower severity
function loadConfig() {
  // MEDIUM: File read - not inside tool, lower risk
  const data = fs.readFileSync("config.json", "utf8");
  return JSON.parse(data);
}

// Export tools for agent
export const tools = [
  shellTool,
  fileWriteTool,
  apiTool,
  axiosTool,
  evalTool,
];
