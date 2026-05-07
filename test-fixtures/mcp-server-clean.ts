/**
 * Test fixture: Clean MCP server with no dangerous operations.
 * Expected: 0 critical/high findings. May have INFO-level CEEs.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({
  name: "clean-mcp-server",
  version: "1.0.0",
});

function formatGreeting(name: string): string {
  return `Hello, ${name}! Welcome to the MCP server.`;
}

function calculateSum(a: number, b: number): number {
  return a + b;
}

server.tool(
  "greet",
  "Generate a greeting message",
  { name: z.string() },
  async ({ name }) => {
    const greeting = formatGreeting(name);
    return { content: [{ type: "text", text: greeting }] };
  }
);

server.tool(
  "add",
  "Add two numbers together",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => {
    const result = calculateSum(a, b);
    return { content: [{ type: "text", text: `${a} + ${b} = ${result}` }] };
  }
);
