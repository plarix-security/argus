# 12-heterogeneous-multi-framework

Multi-service orchestration across LangGraph (Python), CrewAI (Python), and Vercel AI SDK (TypeScript).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    LangGraph Orchestrator               │
│                     (Python, port 8000)                 │
└───────────────┬─────────────────────┬───────────────────┘
                │                     │
        ┌───────▼───────┐     ┌───────▼───────┐
        │ CrewAI Service│     │ Vercel Service│
        │ (Python 8001) │     │   (TS 8002)   │
        └───────────────┘     └───────────────┘
                │                     │
                └──────────┬──────────┘
                           ▼
                   Shared SQLite DB
```

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| HETERO-001 | CRITICAL | httpx.post | Unsigned delegation to CrewAI |
| HETERO-002 | CRITICAL | httpx.post | Unsigned delegation to Vercel |
| HETERO-003 | CRITICAL | cursor.execute | Shared DB write |
| HETERO-004 | WARNING | cursor.execute | Shared state read |
| HETERO-005 | WARNING | requests.post | Result callback |
| HETERO-006 | WARNING | Path.write_text | Audit log write |
| HETERO-007 | INFO | fetch | Bidirectional callback |

## Running

```bash
docker-compose up
```
