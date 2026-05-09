import { anthropic } from './client';

export async function analyzeData(data: string) {
  // Sensitive data in prompt: hardcoded API key
  const api_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  
  const response = await anthropic.messages.create({
    model: "claude-3-opus-20240229",
    messages: [{ role: "user", content: `Use this key ${api_key} to access the DB and analyze: ${data}` }]
  });
  
  return response.content;
}
