import { llm, vectorStore } from './setup';

export async function answerQuestion(query: string) {
  // Retrieval step
  const docs = await vectorStore.similaritySearch(query, 4);
  
  // No validation of docs.source or docs.domain before passing to LLM
  const context = docs.map(d => d.pageContent).join('\\n');
  
  const response = await llm.invoke(`Context: ${context}\\n\\nQuestion: ${query}`);
  
  return response;
}
