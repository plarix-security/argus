# WyScan Benchmark Suite

This benchmark directory is used to validate the current shipped scanner, which is Python-first and explicitly skips TypeScript and JavaScript for findings.

## Current Validation Scope

- Python fixtures with source code are used for finding-count validation.
- Selected Python fixtures can also require CEE identities or a minimum CEE inventory.
- Mixed-language or unsupported-language fixtures are tracked only as informational fixtures in the current Python-first release.
- Fixtures that currently ship without analyzable source code are recorded as asset-limited cases, not as proof of language support or skipped-language behavior.

## Systems In This Snapshot

| # | System | Declared language | Current validation use |
|---|--------|-------------------|------------------------|
| 00 | langgraph-production | Python | CEE baseline validation with minimum inventory |
| 01 | react-tool-agent | Python | Exact count validation |
| 02 | langchain-rag-agent | Python | Exact count validation |
| 03 | langgraph-supervisor | Python | Exact count validation |
| 04 | crewai-research-crew | Python | Exact count validation |
| 05 | openai-assistants-parallel | TypeScript | Asset-limited informational fixture |
| 06 | autogen-code-executor | Python | Exact count validation |
| 07 | langgraph-memory-agent | Python | Exact count validation |
| 08 | typescript-browser-agent | TypeScript | Asset-limited informational fixture |
| 09 | multi-agent-pipeline-fastapi | Python | Exact count validation |
| 10 | rust-agent-runtime | Rust | Asset-limited informational fixture |
| 11 | smolagents-computer-use | Python | Exact count validation |
| 12 | heterogeneous-multi-framework | Python + TypeScript | Asset-limited informational fixture |
| 13 | kubernetes-gitops-agent | Python | CEE identity validation |
| 14 | code-execution-sandbox | Python | CEE identity validation |
| 15 | data-pipeline-etl | Python | CEE identity validation (partial - see limitations) |

## Known Limitations

### Benchmark 15: SQLite Cursor Detection

Benchmark 15 expects detection of `sqlite3.Cursor.execute()` and `sqlite3.Connection.executescript()` operations. The scanner currently has a limitation in tracking method calls on objects returned from context managers:

```python
with sqlite_connection() as conn:  # Context manager
    cursor = conn.cursor()          # Get cursor object
    cursor.execute(query, params)   # Not currently detected
```

The scanner correctly detects direct sqlite3 API calls but does not yet perform interprocedural type tracking through context managers. This is a known limitation that will be addressed in a future release.

## Running The Validator

Build the scanner first, then run:

```bash
python benchmark/scripts/evaluate.py
```

The validator runs the current CLI against each benchmark directory and writes `benchmark/BENCHMARK_RESULTS.md`.
