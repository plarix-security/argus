/**
 * Email tools for OpenAI Assistants customer support agent
 * Demonstrates email exfiltration vulnerability
 */

import OpenAI from 'openai';
import nodemailer from 'nodemailer';

const client = new OpenAI();

const transporter = nodemailer.createTransport({
  host: 'smtp.example.com',
  port: 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'send_email',
      description: 'Send an email to a customer',
      parameters: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } } }
    }
  }
];

async function send_email(to: string, subject: string, body: string) {
  // VULNERABILITY: No allowlist validation on recipient address
  // Agent can send email to any address from conversation context
  const info = await transporter.sendMail({
    from: 'support@company.com',
    to: to,
    subject: subject,
    text: body
  });
  return { messageId: info.messageId };
}

async function runEmailAssistant(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

export { send_email, runEmailAssistant };
