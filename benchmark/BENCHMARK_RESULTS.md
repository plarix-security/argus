# WyScan Benchmark Results

**Run Date:** 2026-03-28
**Systems Evaluated:** 15
**Systems with Code:** 7
**Systems Scored:** 4 (Python with manifest)

## Summary

| # | System | Lang | Expected | Detected | FP | DR | FPR | WS | Status |
|---|--------|------|----------|----------|----|----|-----|----|---------
| 00 | langgraph-production      | ???    |        — |       34 |  — |    — |    — |    — | NO MANIFEST |
| 01 | react-tool-agent          | python |        7 |      5.5 |  2 | 0.79 | 0.25 | 0.59 | PASS |
| 02 | langchain-rag-agent       | python |        8 |      4.0 |  0 | 0.50 | 0.00 | 0.50 | PASS |
| 03 | langgraph-supervisor      | python |        7 |      4.0 |  4 | 0.57 | 0.36 | 0.36 | FAIL |
| 04 | crewai-research-crew      | python |        6 |      5.0 |  6 | 0.83 | 0.50 | 0.42 | PASS |
| 05 | openai-assistants-paralle | typesc |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 06 | autogen-code-executor     | python |        4 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 07 | langgraph-memory-agent    | python |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 08 | typescript-browser-agent  | typesc |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 09 | multi-agent-pipeline-fast | python |        6 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 10 | rust-agent-runtime        | rust   |        4 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 11 | smolagents-computer-use   | python |        5 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| 12 | heterogeneous-multi-frame | python |        7 |      N/A | N/A |  N/A |  N/A |  N/A | NO CODE |
| — | python-agent              | ???    |        — |        6 |  — |    — |    — |    — | NO MANIFEST |
| — | typescript-agent          | ???    |        — |        0 |  — |    — |    — |    — | NO MANIFEST |

## Aggregate Scores (Python Systems Only)

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Detection Rate (DR) | 0.67 | — | — |
| False Positive Rate (FPR) | 0.28 | ≤ 0.10 | FAIL |
| Weighted Score (WS) | 0.47 | ≥ 0.80 | FAIL |
| All Systems Above Floor | No | WS ≥ 0.40 | FAIL |

**Overall Status: FAIL**

## Per-System Details

### 01-react-tool-agent

**Expected:** 7 | **Detected:** 5.5 | **False Positives:** 2
**DR:** 0.79 | **FPR:** 0.25 | **WS:** 0.59

**Matches:**

- [FULL] REACT-001: `eval` @ src/tools/calculator.py:25
  → Found: `eval` @ line 26
- [PARTIAL] REACT-002: `subprocess.run` @ src/tools/calculator.py:38
  → Found: `subprocess.run` @ line 46
- [FULL] REACT-003: `Path.write_text` @ src/tools/file_writer.py:32
  → Found: `filepath.write_text` @ line 31
- [FULL] REACT-004: `filepath.parent.mkdir` @ src/tools/file_writer.py:30
  → Found: `filepath.parent.mkdir` @ line 28
- [FULL] REACT-005: `httpx.get` @ src/tools/web_search.py:28
  → Found: `httpx.get` @ line 25
- [FULL] REACT-006: `Path.read_text` @ src/tools/file_writer.py:48
  → Found: `filepath.read_text` @ line 52

**Missed:**

- REACT-007: `base_path.glob` @ src/tools/file_writer.py:62

**False Positives:**

- `os.getenv` @ web_search.py:20
- `list` @ file_writer.py:71

### 02-langchain-rag-agent

**Expected:** 8 | **Detected:** 4.0 | **False Positives:** 0
**DR:** 0.50 | **FPR:** 0.00 | **WS:** 0.50

**Matches:**

- [PARTIAL] RAG-001: `exec` @ src/tools/document_rewriter.py:35
  → Found: `exec` @ line 42
- [PARTIAL] RAG-002: `doc_path.write_text` @ src/tools/document_rewriter.py:55
  → Found: `doc_path.write_text` @ line 63
- [FULL] RAG-003: `requests.get` @ src/tools/web_search.py:28
  → Found: `requests.get` @ line 23
- [PARTIAL] RAG-004: `requests.get` @ src/tools/web_search.py:48
  → Found: `requests.get` @ line 42
- [PARTIAL] RAG-005: `new_doc_path.write_text` @ src/tools/document_rewriter.py:70
  → Found: `new_doc_path.write_text` @ line 80
- [FULL] RAG-006: `doc_path.read_text` @ src/tools/document_rewriter.py:25
  → Found: `doc_path.read_text` @ line 23

**Missed:**

- RAG-007: `Path.read_text` @ src/agent.py:45
- RAG-008: `Path.glob` @ src/agent.py:82

### 03-langgraph-supervisor

**Expected:** 7 | **Detected:** 4.0 | **False Positives:** 4
**DR:** 0.57 | **FPR:** 0.36 | **WS:** 0.36

**Matches:**

- [PARTIAL] SUPER-001: `subprocess.run` @ src/agents/coder_agent.py:42
  → Found: `subprocess.run` @ line 33
- [FULL] SUPER-002: `exec` @ src/agents/coder_agent.py:58
  → Found: `exec` @ line 63
- [PARTIAL] SUPER-003: `requests.get` @ src/agents/researcher_agent.py:35
  → Found: `requests.get` @ line 20
- [PARTIAL] SUPER-004: `Path.write_text` @ src/agents/coder_agent.py:75
  → Found: `code_path.write_text` @ line 99
- [PARTIAL] SUPER-005: `state_file.write_text` @ src/tools/shared_state.py:28
  → Found: `STATE_FILE.write_text` @ line 56
- [PARTIAL] SUPER-006: `Path.read_text` @ src/agents/coder_agent.py:68
  → Found: `code_path.read_text` @ line 81
- [PARTIAL] SUPER-007: `state_file.read_text` @ src/tools/shared_state.py:18
  → Found: `STATE_FILE.parent.mkdir` @ line 20

**False Positives:**

- `code_path.parent.mkdir` @ coder_agent.py:97
- `STATE_FILE.parent.mkdir` @ shared_state.py:47
- `STATE_FILE.read_text` @ shared_state.py:25
- `STATE_FILE.read_text` @ shared_state.py:51

### 04-crewai-research-crew

**Expected:** 6 | **Detected:** 5.0 | **False Positives:** 6
**DR:** 0.83 | **FPR:** 0.50 | **WS:** 0.42

**Matches:**

- [FULL] CREW-001: `exec` @ src/tools/scraper.py:45
  → Found: `exec` @ line 50
- [FULL] CREW-002: `requests.post` @ src/tools/webhook.py:25
  → Found: `requests.post` @ line 24
- [FULL] CREW-003: `requests.get` @ src/tools/scraper.py:22
  → Found: `requests.get` @ line 21
- [PARTIAL] CREW-004: `plan_path.write_text` @ src/tools/plan_file.py:28
  → Found: `PLAN_PATH.write_text` @ line 40
- [FULL] CREW-005: `output_path.write_text` @ src/tools/publish.py:22
  → Found: `output_path.write_text` @ line 26
- [PARTIAL] CREW-006: `plan_path.read_text` @ src/tools/plan_file.py:15
  → Found: `PLAN_PATH.parent.mkdir` @ line 16

**False Positives:**

- `PLAN_PATH.parent.mkdir` @ plan_file.py:38
- `OUTPUT_DIR.mkdir` @ publish.py:21
- `requests.post` @ webhook.py:41
- `PLAN_PATH.read_text` @ plan_file.py:21
- `requests.get` @ scraper.py:45
- `os.getenv` @ webhook.py:40

### 05-openai-assistants-parallel

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

### 06-autogen-code-executor

**Status:** No source code implemented
**Expected CEEs:** 4
**Note:** This system has a manifest but no code to scan.

### 07-langgraph-memory-agent

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

### 08-typescript-browser-agent

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

### 09-multi-agent-pipeline-fastapi

**Status:** No source code implemented
**Expected CEEs:** 6
**Note:** This system has a manifest but no code to scan.

### 10-rust-agent-runtime

**Status:** No source code implemented
**Expected CEEs:** 4
**Note:** This system has a manifest but no code to scan.

### 11-smolagents-computer-use

**Status:** No source code implemented
**Expected CEEs:** 5
**Note:** This system has a manifest but no code to scan.

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
