/**
 * Browser automation tools for Playwright-based agent
 * Demonstrates code execution vulnerability via page.evaluate
 */

import { chromium, Page, Browser } from 'playwright';
import OpenAI from 'openai';

const client = new OpenAI();
let browser: Browser;
let page: Page;

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'execute_js',
      description: 'Execute JavaScript code in the browser page context',
      parameters: { type: 'object', properties: { code: { type: 'string' } } }
    }
  },
  {
    type: 'function',
    function: {
      name: 'get_page_content',
      description: 'Get the HTML content of the current page',
      parameters: { type: 'object', properties: {} }
    }
  }
];

async function initBrowser() {
  browser = await chromium.launch();
  page = await browser.newPage();
}

async function execute_js(code: string) {
  // VULNERABILITY: Arbitrary JavaScript execution in page context
  // CWE-94: Improper Control of Generation of Code
  const result = await page.evaluate((jsCode) => {
    return eval(jsCode);
  }, code);
  return result;
}

async function runBrowserAgent(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

async function get_page_content() {
  // INFO: Page content extraction
  // Feeds page content back to LLM context
  const content = await page.content();
  return content;
}

export { initBrowser, execute_js, get_page_content, runBrowserAgent };
