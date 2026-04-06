/**
 * Escalation tools for OpenAI Assistants customer support agent
 * Demonstrates filesystem write vulnerability
 */

import OpenAI from 'openai';
import * as fs from 'fs';

const client = new OpenAI();

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'escalate_to_human',
      description: 'Escalate the conversation to a human agent',
      parameters: { type: 'object', properties: { reason: { type: 'string' }, priority: { type: 'string' } } }
    }
  }
];

async function escalate_to_human(reason: string, priority: string) {
  // VULNERABILITY: Agent can write to filesystem
  const ticket = JSON.stringify({
    timestamp: new Date().toISOString(),
    reason,
    priority
  });
  fs.appendFileSync('/var/queue/escalations.json', ticket + '\n');
  return { status: 'escalated' };
}

async function runEscalationAssistant(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

export { escalate_to_human, runEscalationAssistant };
