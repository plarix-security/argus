/**
 * Test fixture: Prompt Injection (OWASP-L1)
 * Expected: CRITICAL finding — unsanitized req.body flows into LLM call.
 *
 * Taint flow:
 *   req.body.prompt → userPrompt → template literal → openai.chat.completions.create
 */
import { openai } from './client';

export async function handleRequest(req: any, res: any) {
  // External input from req.body — this is the taint source
  const userPrompt = req.body.prompt;

  // Intermediate variable (taint propagates)
  const formattedPrompt = `You are a helpful assistant. User says: ${userPrompt}`;

  // Prompt injection path: no sanitization, flows directly to LLM
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: formattedPrompt }]
  });

  res.json({ result: response });
}
