import { openai } from './client';

export async function handleRequest(req, res) {
  // External input from req.body
  const userPrompt = req.body.prompt;
  
  // Prompt injection path: no sanitization, flows directly to LLM
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: userPrompt }]
  });
  
  res.json({ result: response });
}
