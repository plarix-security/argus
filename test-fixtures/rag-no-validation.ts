/**
 * Test fixture: RAG without Source Validation (OWASP-L8)
 * Expected: WARNING finding — vector store retrieval flows into LLM without validation.
 *
 * Taint flow:
 *   vectorStore.similaritySearch → docs → context (map/join) → llm.invoke
 */
import { llm, vectorStore } from './setup';

export async function answerQuestion(query: string) {
  // Retrieval step — this is the RAG taint source
  const docs = await vectorStore.similaritySearch(query, 4);

  // No validation of docs.source or docs.domain before passing to LLM
  const context = docs.map((d: any) => d.pageContent).join('\\n');

  // RAG content flows directly into LLM without source filtering
  const response = await llm.invoke(`Context: ${context}\\n\\nQuestion: ${query}`);

  return response;
}
