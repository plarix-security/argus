/**
 * Form interaction tools for Playwright-based agent
 * Demonstrates credential filling vulnerability
 */

import { Page } from 'playwright';
import OpenAI from 'openai';

const client = new OpenAI();
let page: Page;

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'fill_form',
      description: 'Fill a form field with a value',
      parameters: { type: 'object', properties: { selector: { type: 'string' }, value: { type: 'string' } } }
    }
  }
];

async function fill_form(selector: string, value: string) {
  // WARNING: Form filling including potential credential fields
  // Agent can fill any form field including passwords
  await page.fill(selector, value);
  return { filled: true, selector };
}

async function runFormAgent(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

export { fill_form, runFormAgent };
