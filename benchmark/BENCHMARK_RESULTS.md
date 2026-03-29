# WyScan Benchmark Results

**Run Date:** 2026-03-29
**Systems Evaluated:** 15
**Systems with Code:** 11
**Systems Scored:** 8 (Python with manifest)

## Summary

| # | System | Lang | Expected | Detected | FP | DR | FPR | WS | Status |
|---|--------|------|----------|----------|----|----|-----|----|---------
| 00 | langgraph-production      | ???    |        — |       34 |  — |    — |    — |    — | NO MANIFEST |
| 01 | react-tool-agent          | python |        7 |      7.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 02 | langchain-rag-agent       | python |        6 |      6.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 03 | langgraph-supervisor      | python |       11 |     11.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 04 | crewai-research-crew      | python |       11 |     11.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 05 | openai-assistants-paralle | typesc |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 06 | autogen-code-executor     | python |        5 |      5.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 07 | langgraph-memory-agent    | python |        5 |      5.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 08 | typescript-browser-agent  | typesc |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 09 | multi-agent-pipeline-fast | python |        7 |      7.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 10 | rust-agent-runtime        | rust   |        4 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 11 | smolagents-computer-use   | python |        5 |      5.0 |  0 | 1.00 | 0.00 | 1.00 | PASS |
| 12 | heterogeneous-multi-frame | python |        7 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| — | python-agent              | ???    |        — |        6 |  — |    — |    — |    — | NO MANIFEST |
| — | typescript-agent          | ???    |        — |        0 |  — |    — |    — |    — | NO MANIFEST |

## Aggregate Scores (Python Systems Only)

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Detection Rate (DR) | 1.00 | — | — |
| False Positive Rate (FPR) | 0.00 | ≤ 0.10 | PASS |
| Weighted Score (WS) | 1.00 | ≥ 0.80 | PASS |
| All Systems Above Floor | Yes | WS ≥ 0.40 | PASS |

**Overall Status: PASS**

## Per-System Details

### 01-react-tool-agent

**Expected:** 7 | **Detected:** 7.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] REACT-001: `eval` @ src/tools/calculator.py:26
  → Found: `eval` @ line 26
- [FULL] REACT-002: `subprocess.run` @ src/tools/calculator.py:46
  → Found: `subprocess.run` @ line 46
- [FULL] REACT-003: `filepath.parent.mkdir` @ src/tools/file_writer.py:28
  → Found: `filepath.parent.mkdir` @ line 28
- [FULL] REACT-004: `filepath.write_text` @ src/tools/file_writer.py:31
  → Found: `filepath.write_text` @ line 31
- [FULL] REACT-005: `httpx.get` @ src/tools/web_search.py:25
  → Found: `httpx.get` @ line 25
- [FULL] REACT-006: `filepath.read_text` @ src/tools/file_writer.py:52
  → Found: `filepath.read_text` @ line 52
- [FULL] REACT-007: `list` @ src/tools/file_writer.py:71
  → Found: `list` @ line 71

### 02-langchain-rag-agent

**Expected:** 6 | **Detected:** 6.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] RAG-001: `exec` @ src/tools/document_rewriter.py:42
  → Found: `exec` @ line 42
- [FULL] RAG-002: `doc_path.write_text` @ src/tools/document_rewriter.py:63
  → Found: `doc_path.write_text` @ line 63
- [FULL] RAG-003: `new_doc_path.write_text` @ src/tools/document_rewriter.py:80
  → Found: `new_doc_path.write_text` @ line 80
- [FULL] RAG-004: `requests.get` @ src/tools/web_search.py:23
  → Found: `requests.get` @ line 23
- [FULL] RAG-005: `requests.get` @ src/tools/web_search.py:42
  → Found: `requests.get` @ line 42
- [FULL] RAG-006: `doc_path.read_text` @ src/tools/document_rewriter.py:23
  → Found: `doc_path.read_text` @ line 23

### 03-langgraph-supervisor

**Expected:** 11 | **Detected:** 11.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] SUPER-001: `subprocess.run` @ src/agents/coder_agent.py:33
  → Found: `subprocess.run` @ line 33
- [FULL] SUPER-002: `exec` @ src/agents/coder_agent.py:63
  → Found: `exec` @ line 63
- [FULL] SUPER-003: `requests.get` @ src/agents/researcher_agent.py:20
  → Found: `requests.get` @ line 20
- [FULL] SUPER-004: `code_path.parent.mkdir` @ src/agents/coder_agent.py:97
  → Found: `code_path.parent.mkdir` @ line 97
- [FULL] SUPER-005: `code_path.write_text` @ src/agents/coder_agent.py:99
  → Found: `code_path.write_text` @ line 99
- [FULL] SUPER-006: `STATE_FILE.parent.mkdir` @ src/tools/shared_state.py:20
  → Found: `STATE_FILE.parent.mkdir` @ line 20
- [FULL] SUPER-007: `STATE_FILE.parent.mkdir` @ src/tools/shared_state.py:47
  → Found: `STATE_FILE.parent.mkdir` @ line 47
- [FULL] SUPER-008: `STATE_FILE.write_text` @ src/tools/shared_state.py:56
  → Found: `STATE_FILE.write_text` @ line 56
- [FULL] SUPER-009: `code_path.read_text` @ src/agents/coder_agent.py:81
  → Found: `code_path.read_text` @ line 81
- [FULL] SUPER-010: `STATE_FILE.read_text` @ src/tools/shared_state.py:25
  → Found: `STATE_FILE.read_text` @ line 25
- [FULL] SUPER-011: `STATE_FILE.read_text` @ src/tools/shared_state.py:51
  → Found: `STATE_FILE.read_text` @ line 51

### 04-crewai-research-crew

**Expected:** 11 | **Detected:** 11.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] CREW-001: `exec` @ src/tools/scraper.py:50
  → Found: `exec` @ line 50
- [FULL] CREW-002: `PLAN_PATH.parent.mkdir` @ src/tools/plan_file.py:16
  → Found: `PLAN_PATH.parent.mkdir` @ line 16
- [FULL] CREW-003: `PLAN_PATH.parent.mkdir` @ src/tools/plan_file.py:38
  → Found: `PLAN_PATH.parent.mkdir` @ line 38
- [FULL] CREW-004: `PLAN_PATH.write_text` @ src/tools/plan_file.py:40
  → Found: `PLAN_PATH.write_text` @ line 40
- [FULL] CREW-005: `OUTPUT_DIR.mkdir` @ src/tools/publish.py:21
  → Found: `OUTPUT_DIR.mkdir` @ line 21
- [FULL] CREW-006: `output_path.write_text` @ src/tools/publish.py:26
  → Found: `output_path.write_text` @ line 26
- [FULL] CREW-007: `requests.get` @ src/tools/scraper.py:21
  → Found: `requests.get` @ line 21
- [FULL] CREW-008: `requests.get` @ src/tools/scraper.py:45
  → Found: `requests.get` @ line 45
- [FULL] CREW-009: `requests.post` @ src/tools/webhook.py:24
  → Found: `requests.post` @ line 24
- [FULL] CREW-010: `requests.post` @ src/tools/webhook.py:41
  → Found: `requests.post` @ line 41
- [FULL] CREW-011: `PLAN_PATH.read_text` @ src/tools/plan_file.py:21
  → Found: `PLAN_PATH.read_text` @ line 21

### 05-openai-assistants-parallel

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

### 06-autogen-code-executor

**Expected:** 5 | **Detected:** 5.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] AUTOGEN-001: `exec` @ src/executor.py:26
  → Found: `exec` @ line 26
- [FULL] AUTOGEN-002: `eval` @ src/executor.py:44
  → Found: `eval` @ line 44
- [FULL] AUTOGEN-003: `mkdir` @ src/executor.py:54
  → Found: `output_dir.mkdir` @ line 54
- [FULL] AUTOGEN-004: `Path.write_text` @ src/executor.py:58
  → Found: `filepath.write_text` @ line 58
- [FULL] AUTOGEN-005: `Path.read_text` @ src/executor.py:73
  → Found: `filepath.read_text` @ line 73

### 07-langgraph-memory-agent

**Expected:** 5 | **Detected:** 5.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] MEMORY-001: `redis_client.set` @ src/tools/memory.py:31
  → Found: `redis_client.set` @ line 31
- [FULL] MEMORY-002: `redis_client.get` @ src/tools/memory.py:49
  → Found: `redis_client.get` @ line 49
- [FULL] MEMORY-003: `redis_client.delete` @ src/tools/memory.py:67
  → Found: `redis_client.delete` @ line 67
- [FULL] MEMORY-004: `redis_client.keys` @ src/tools/reflect.py:23
  → Found: `redis_client.keys` @ line 23
- [FULL] MEMORY-005: `httpx.get` @ src/agent.py:38
  → Found: `httpx.get` @ line 38

### 08-typescript-browser-agent

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

### 09-multi-agent-pipeline-fastapi

**Expected:** 7 | **Detected:** 7.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] FASTAPI-001: `eval` @ src/agents/data_analyst.py:37
  → Found: `eval` @ line 37
- [FULL] FASTAPI-002: `subprocess.run` @ src/agents/orchestrator.py:50
  → Found: `subprocess.run` @ line 50
- [FULL] FASTAPI-003: `httpx.post` @ src/agents/orchestrator.py:76
  → Found: `httpx.post` @ line 76
- [FULL] FASTAPI-004: `requests.post` @ src/agents/content_generator.py:41
  → Found: `requests.post` @ line 41
- [FULL] FASTAPI-005: `cursor.execute` @ src/agents/data_analyst.py:66
  → Found: `cursor.execute` @ line 66
- [FULL] FASTAPI-006: `cursor.fetchall` @ src/agents/data_analyst.py:67
  → Found: `cursor.fetchall` @ line 67
- [FULL] FASTAPI-007: `config_path.read_text` @ src/api/routes.py:31
  → Found: `config_path.read_text` @ line 31

### 10-rust-agent-runtime

**Status:** No source code implemented
**Expected CEEs:** 4
**Note:** This system has a manifest but no code to scan.

### 11-smolagents-computer-use

**Expected:** 5 | **Detected:** 5.0 | **False Positives:** 0
**DR:** 1.00 | **FPR:** 0.00 | **WS:** 1.00

**Matches:**

- [FULL] SMOL-001: `exec` @ src/agent.py:34
  → Found: `exec` @ line 34
- [FULL] SMOL-002: `subprocess.run` @ src/tools/system.py:23
  → Found: `subprocess.run` @ line 23
- [FULL] SMOL-003: `filepath.write_text` @ src/tools/files.py:18
  → Found: `filepath.write_text` @ line 18
- [FULL] SMOL-004: `httpx.get` @ src/tools/web.py:15
  → Found: `httpx.get` @ line 15
- [FULL] SMOL-005: `filepath.read_text` @ src/tools/files.py:31
  → Found: `filepath.read_text` @ line 31

### 12-heterogeneous-multi-framework

**Status:** No source code implemented
**Expected CEEs:** 7
**Note:** This system has a manifest but no code to scan.

## Notes

### Scoring Formula

```
Detection Rate (DR) = detected_cees / expected_cees
False Positive Rate (FPR) = false_positives / total_findings
Weighted Score (WS) = DR × (1 - FPR)
```

### Match Criteria

A WyScan finding matches a manifest CEE if:
- **operation**: exact string match
- **afb_type**: exact (AFB04)
- **location**: same file AND within ±5 lines

- 3/3 match = 1.0 points (full)
- 2/3 match = 0.5 points (partial)
- <2 match = 0.0 points (miss)

### Language Support

WyScan currently supports **Python only**. TypeScript and Rust systems return
no findings by design — this prevents false positives from pattern matching
without proper AST analysis.
