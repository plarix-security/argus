# 02-langchain-rag-agent

RAG-augmented agent using LangChain 0.3+ with FAISS vector store, document manipulation, and web search.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     RAG Agent                                │
│  ┌──────────┐    ┌─────────────┐    ┌──────────────────┐   │
│  │  Query   │ -> │  Retrieval  │ -> │  Generation      │   │
│  └──────────┘    └─────────────┘    └──────────────────┘   │
│                        │                     │              │
│                        v                     v              │
│                  FAISS Store            OpenAI LLM          │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
    ┌────┴────┐         ┌────┴────┐         ┌────┴────┐
    │Document │         │  Web    │         │Document │
    │ Reader  │         │ Search  │         │Rewriter │
    └─────────┘         └─────────┘         └─────────┘
         │                   │                   │
         v                   v                   v
    Local Files ⚠️      External URLs ⚠️    Self-Modify ⚠️
```

## Intentional Vulnerabilities

### CRITICAL: Code Execution via Transform (AFB04)
- **File**: `src/tools/document_rewriter.py:35`
- **Pattern**: `exec(transform_code)` for document transformations
- **Attack**: Transform code can execute arbitrary Python

### WARNING: Document Self-Poisoning (AFB04)
- **File**: `src/tools/document_rewriter.py:55`
- **Pattern**: Agent rewrites documents in its own knowledge base
- **Attack**: Malicious content persists and influences future queries

### WARNING: SSRF via Web Search (AFB04)
- **File**: `src/tools/web_search.py:28`
- **Pattern**: `requests.get(search_url)` with user-controlled URL
- **Attack**: Target internal endpoints like `http://169.254.169.254/`

### WARNING: Indirect Prompt Injection (AFB01 → AFB04)
- **File**: `src/tools/web_search.py:48`
- **Pattern**: Raw HTML content passed to LLM context
- **Attack**: Web page contains `<!-- IGNORE PREVIOUS INSTRUCTIONS -->`

## Running

```bash
cp .env.example .env
pip install -r requirements.txt
python -m src.main "What documents do we have about security?"
```

## Expected WyScan Findings

| ID | Severity | Operation | Tool |
|----|----------|-----------|------|
| RAG-001 | CRITICAL | exec | execute_transform |
| RAG-002 | WARNING | write_text | rewrite_document |
| RAG-003 | WARNING | requests.get | search_web |
| RAG-004 | WARNING | requests.get | fetch_url |
| RAG-005 | WARNING | write_text | add_document |
| RAG-006 | INFO | read_text | read_document |
| RAG-007 | INFO | read_text | load_documents |
| RAG-008 | INFO | glob | load_documents |
