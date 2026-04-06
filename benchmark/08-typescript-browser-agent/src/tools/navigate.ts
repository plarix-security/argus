/**
 * Navigation tools for Playwright-based agent
 * Demonstrates SSRF vulnerability via page.goto
 */

import { Page } from 'playwright';
import OpenAI from 'openai';

const client = new OpenAI();
let page: Page;

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'navigate',
      description: 'Navigate the browser to a URL',
      parameters: { type: 'object', properties: { url: { type: 'string' } } }
    }
  }
];

async function navigate(url: string) {
  // VULNERABILITY: SSRF via browser navigation
  // CWE-918: Server-Side Request Forgery
  // URL comes directly from LLM without validation
  await page.goto(url);
  return { navigated: true, url };
}

async function runNavigationAgent(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

export { navigate, runNavigationAgent };
