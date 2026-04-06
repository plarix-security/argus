/**
 * Screenshot tools for Playwright-based agent
 * Demonstrates arbitrary screenshot capture
 */

import { Page } from 'playwright';
import OpenAI from 'openai';

const client = new OpenAI();
let page: Page;

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'take_screenshot',
      description: 'Take a screenshot of the current page',
      parameters: { type: 'object', properties: { path: { type: 'string' } } }
    }
  }
];

async function take_screenshot(path: string) {
  // WARNING: Screenshot capture of arbitrary pages
  // Could capture sensitive data displayed on page
  await page.screenshot({ path });
  return { saved: true, path };
}

async function runScreenshotAgent(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

export { take_screenshot, runScreenshotAgent };
