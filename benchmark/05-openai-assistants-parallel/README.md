# 05-openai-assistants-parallel

OpenAI Assistants v2 customer support agent with parallel tool calls, SQL injection, and email vulnerabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              OpenAI Assistants v2 Agent                      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Parallel Tool Execution                    │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │ │
│  │  │  Order   │ │  Refund  │ │  Email   │ │ Escalate │  │ │
│  │  │  Lookup  │ │ Process  │ │  Send    │ │ to Human │  │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │ │
│  └───────┼────────────┼────────────┼────────────┼────────┘ │
│          v            v            v            v          │
│      SQLite ⚠️    SQLite ⚠️    SMTP ⚠️     File ⚠️       │
│    (injection)   (mutation)  (exfil)   (queue write)      │
└─────────────────────────────────────────────────────────────┘
```

## Intentional Vulnerabilities

### CRITICAL: SQL Injection (AFB04)
- **File**: `src/tools/database.ts:25`
- **Pattern**: `` `SELECT * FROM orders WHERE id = ${orderId}` ``
- **Attack**: `orderId = "1 OR 1=1; DROP TABLE orders;--"`

### CRITICAL: SQL Mutation (AFB04)
- **File**: `src/tools/database.ts:42`
- **Pattern**: UPDATE with interpolated refund amount
- **Attack**: Process unauthorized refunds

### WARNING: Email to Untrusted Address (AFB04)
- **File**: `src/tools/email.ts:28`
- **Pattern**: Email recipient from conversation context
- **Attack**: Send sensitive data to attacker's email

## Running

```bash
cp .env.example .env
npm install
npx ts-node src/main.ts "Help me with order #12345"
```

## Validation Note

This fixture currently does not include analyzable source files in the repository snapshot.

Current benchmark validation status is recorded in `../BENCHMARK_RESULTS.md`.
