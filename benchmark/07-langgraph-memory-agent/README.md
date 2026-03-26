# 07-langgraph-memory-agent

Long-term memory agent using LangGraph with Redis persistence.

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| MEMORY-001 | CRITICAL | redis.set | Persistent memory write without namespace |
| MEMORY-002 | WARNING | redis.get | Memory retrieval from poisoned store |
| MEMORY-003 | WARNING | redis.delete | Memory deletion without ownership check |
| MEMORY-004 | WARNING | redis.keys | Memory enumeration for reflection |
| MEMORY-005 | INFO | httpx.get | External context fetch |

## Running

```bash
docker-compose up -d redis
pip install -r requirements.txt
python -m src.main "Remember that my favorite color is blue"
```
