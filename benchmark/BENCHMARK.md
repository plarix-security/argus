# WyScan Benchmark Suite

Comprehensive test suite for validating WyScan's AFB04 detection capabilities across multiple agent frameworks, languages, and vulnerability patterns.

## Quick Reference

| # | System | Framework | Language | Difficulty | Expected Findings |
|---|--------|-----------|----------|------------|-------------------|
| 00 | langgraph-production | LangGraph/LangChain | Python | 4/5 | 4C / 18W / 12I |
| 01 | react-tool-agent | OpenAI SDK | Python | 1/5 | 2C / 3W / 2I |
| 02 | langchain-rag-agent | LangChain 0.3+ | Python | 2/5 | 1C / 4W / 4I |
| 03 | langgraph-supervisor | LangGraph 0.2+ | Python | 3/5 | 2C / 3W / 3I |
| 04 | crewai-research-crew | CrewAI 0.80+ | Python | 3/5 | 1C / 4W / 3I |
| 05 | openai-assistants-parallel | OpenAI Assistants v2 | TypeScript | 3/5 | 2C / 3W / 2I |
| 06 | autogen-code-executor | AutoGen 0.4+ | Python | 4/5 | 2C / 1W / 1I |
| 07 | langgraph-memory-agent | LangGraph + Redis | Python | 4/5 | 1C / 3W / 1I |
| 08 | typescript-browser-agent | Playwright + OpenAI | TypeScript | 4/5 | 2C / 2W / 1I |
| 09 | multi-agent-pipeline-fastapi | FastAPI + LangGraph | Python | 5/5 | 2C / 3W / 1I |
| 10 | rust-agent-runtime | async-openai + tokio | Rust | 5/5 | 1C / 2W / 1I |
| 11 | smolagents-computer-use | smolagents CodeAgent | Python | 5/5 | 2C / 2W / 1I |
| 12 | heterogeneous-multi-framework | Multi-framework | Python+TS | 5/5 | 3C / 3W / 1I |

**Legend**: C = Critical, W = Warning, I = Info

## Running

```bash
./benchmark/scripts/run-benchmark.sh
```

## License

Internal use only. Part of the WyScan security scanner test suite.
