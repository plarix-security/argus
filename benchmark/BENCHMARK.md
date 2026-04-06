# WyScan Benchmark Suite

This benchmark directory is used to validate the shipped scanner across Python, TypeScript, and JavaScript codebases.

## Current Validation Scope

- Python fixtures with source code are used for finding-count validation.
- TypeScript fixtures with source code are used for finding-count validation.
- Selected fixtures can also require CEE identities or a minimum CEE inventory.
- Mixed-language fixtures (like benchmark 12) validate cross-language project support.

## Systems In This Snapshot

| # | System | Declared language | Current validation use |
|---|--------|-------------------|------------------------|
| 00 | langgraph-production | Python | CEE baseline validation with minimum inventory |
| 01 | react-tool-agent | Python | Exact count validation |
| 02 | langchain-rag-agent | Python | Exact count validation |
| 03 | langgraph-supervisor | Python | Exact count validation |
| 04 | crewai-research-crew | Python | Exact count validation |
| 05 | openai-assistants-parallel | TypeScript | Exact count validation |
| 06 | autogen-code-executor | Python | Exact count validation |
| 07 | langgraph-memory-agent | Python | Exact count validation |
| 08 | typescript-browser-agent | TypeScript | Exact count validation |
| 09 | multi-agent-pipeline-fastapi | Python | Exact count validation |
| 10 | rust-agent-runtime | Rust | Asset-limited informational fixture |
| 11 | smolagents-computer-use | Python | Exact count validation |
| 12 | heterogeneous-multi-framework | Python + TypeScript | Mixed-language validation |
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

### Benchmark 10: Rust Support

Rust analysis is not currently implemented. Benchmark 10 serves as an informational fixture for future Rust support.

## Running The Validator

Build the scanner first, then run:

```bash
python benchmark/scripts/evaluate.py
```

The validator runs the current CLI against each benchmark directory and writes `benchmark/BENCHMARK_RESULTS.md`.
