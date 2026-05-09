/**
 * Test fixture: Clean agent with no dangerous operations.
 * Expected: 0 CRITICAL findings. Should pass CI/CD checks.
 */
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

function formatResponse(data: string): string {
  return `Processed: ${data.toUpperCase()}`;
}

function calculateAge(birthYear: number): number {
  return new Date().getFullYear() - birthYear;
}

const formatterTool = new DynamicStructuredTool({
  name: "format_text",
  description: "Format text for display",
  schema: z.object({ text: z.string() }),
  func: async ({ text }) => {
    return formatResponse(text);
  },
});

const ageTool = new DynamicStructuredTool({
  name: "calculate_age",
  description: "Calculate age from birth year",
  schema: z.object({ birthYear: z.number() }),
  func: async ({ birthYear }) => {
    return `Age: ${calculateAge(birthYear)}`;
  },
});

export { formatterTool, ageTool };
