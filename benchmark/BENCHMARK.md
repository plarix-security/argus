# WyScan Benchmark Suite

This benchmark directory is used to validate the current shipped scanner, which is Python-first and explicitly skips TypeScript and JavaScript for findings.

## Current Validation Scope

- Python fixtures with source code are used for finding-count validation.
- Mixed-language or unsupported-language fixtures are used only when source code is present in the repository snapshot.
- Fixtures that currently ship without analyzable source code are recorded as asset-limited cases, not as proof of language support.

## Systems In This Snapshot

| # | System | Declared language | Current validation use |
|---|--------|-------------------|------------------------|
| 00 | langgraph-production | Python | Operational smoke run; no manifest in repo snapshot |
| 01 | react-tool-agent | Python | Exact count validation |
| 02 | langchain-rag-agent | Python | Exact count validation |
| 03 | langgraph-supervisor | Python | Exact count validation |
| 04 | crewai-research-crew | Python | Exact count validation |
| 05 | openai-assistants-parallel | TypeScript | Asset-limited; no analyzable source files in repo snapshot |
| 06 | autogen-code-executor | Python | Exact count validation |
| 07 | langgraph-memory-agent | Python | Exact count validation |
| 08 | typescript-browser-agent | TypeScript | Asset-limited; no analyzable source files in repo snapshot |
| 09 | multi-agent-pipeline-fastapi | Python | Exact count validation |
| 10 | rust-agent-runtime | Rust | Asset-limited; no analyzable source files in repo snapshot |
| 11 | smolagents-computer-use | Python | Exact count validation |
| 12 | heterogeneous-multi-framework | Python + TypeScript | Asset-limited; no analyzable source files in repo snapshot |

## Running The Validator

Build the scanner first, then run:

```bash
python benchmark/scripts/evaluate.py
```

The validator runs the current CLI against each benchmark directory and writes `benchmark/BENCHMARK_RESULTS.md`.
