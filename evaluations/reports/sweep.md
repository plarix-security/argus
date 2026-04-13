# Wyscan Security Report: Sweep

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/sweepai/sweep
> **Framework(s) detected:** sweepai

## About This System

Sweep is an AI-powered GitHub assistant and junior developer that automatically converts GitHub issues into pull requests. It reads codebases, plans changes, writes code, and opens PRs with minimal human involvement. It was selected for AFB04 evaluation because it operates with write access to production codebases and interacts directly with GitHub APIs, representing a supply chain risk vector if its decision-making can be influenced through crafted issue text.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 227 |
| Scan duration | 12.1s |
| Total CEEs detected | 18 |
| Classified findings | 15 |
| Unclassified CEEs | 3 |
| Unique entrypoints reaching sensitive ops | N/A (not reported) |
| Unresolved call edges (coverage gap) | 331 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| WARNING | 14 |
| INFO | 0 |
| UNCLASSIFIED | 3 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

Sweep is the only system in this evaluation set with a CRITICAL finding: tool-controlled input flowing directly into `subprocess.run` via the `ripgrep` tool, with no policy gate on the call path. All 14 WARNING findings are in `question_answerer.py`, where multiple sweepai-framework tools accumulate code snippets, file paths, and LLM state into in-memory collections without authorization checks. The `ask_question_about_codebase` tool, which has tool-controlled input traced into `llm_state["questions_and_answers"].append`, represents a direct path from crafted GitHub issue content through LLM context mutation and into subprocess execution arguments.

---

## Critical Findings

### [ripgrep] -> [PROCESS_EXECUTION]

| Field | Value |
|-------|-------|
| File | `question_answerer.py:270` |
| Entry point | `question_answerer.py:261` |
| Framework | sweepai |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | Yes |
| Instruction-influenced | Yes |
| Resource hint | `rg` |

**Code:**
```
subprocess.run(
```

**Risk:** The `ripgrep` tool passes tool-controlled input directly into `subprocess.run` arguments with no policy gate on the call path. An adversary who can influence the agent's instruction channel -- for example, by crafting a malicious GitHub issue -- can potentially inject arguments into the `rg` subprocess call, leading to arbitrary file reads, path traversal, or, depending on shell invocation context, command execution within the environment where Sweep runs. Because Sweep operates with codebase read access and GitHub write access, compromise of this execution path could enable exfiltration of repository secrets or injection of malicious code into pull requests.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

## Warning Findings

### STATE_MUTATION (13 findings)

Thirteen findings capture append operations to in-memory collections (`snippets`, `missing_files`, `bad_files`, `all_ranges`, `snippet_indexes`, `relevant_files`) across four sweepai tools. These collections accumulate code content, file paths, and range metadata derived from LLM-influenced paths, with no policy gate on any call chain. Instruction-influenced input is present in all but one finding (`missing_files.append` from `submit_task`). The `ask_question_about_codebase` tool appends directly to `llm_state["questions_and_answers"]` with tool-controlled input traced, meaning agent-supplied question content flows into the LLM state store that drives subsequent tool calls.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| semantic_search | sweepai | question_answerer.py:160 | snippet.expand(expand_size).denotation | No |
| semantic_search | sweepai | question_answerer.py:166 | f"Snippet already retrieved previously: {snippet.denotation}" | No |
| vector_search | sweepai | question_answerer.py:201 | snippet.expand(expand_size).denotation | No |
| vector_search | sweepai | question_answerer.py:207 | f"Snippet already retrieved previously: {snippet.denotation}" | No |
| submit_task | sweepai | question_answerer.py:360 | file_path | No |
| submit_task | sweepai | question_answerer.py:361 | content | No |
| add_files_to_context | sweepai | question_answerer.py:433 | file_name | No |
| add_files_to_context | sweepai | question_answerer.py:449 | snippet.start | No |
| add_files_to_context | sweepai | question_answerer.py:450 | i | No |
| add_files_to_context | sweepai | question_answerer.py:451 | file_range | No |
| add_files_to_context | sweepai | question_answerer.py:458 | file_contents | No |
| add_files_to_context | sweepai | question_answerer.py:475 | i | No |
| add_files_to_context | sweepai | question_answerer.py:485 | file_contents | No |

### STATE_MUTATION with tool-controlled input (1 finding)

The `ask_question_about_codebase` tool appends to `llm_state["questions_and_answers"]` with tool-controlled input traced into the operation arguments, making this the highest-severity WARNING finding. Content from crafted issue text that reaches the agent's question context flows directly into the persistent LLM state dictionary that coordinates subsequent tool invocations.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| ask_question_about_codebase | sweepai | search_agent.py:204 | question | Yes |

---

## Info Findings

No INFO findings detected.

---

## Unclassified CEEs

**Total:** 3

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (1):**
- `submit_task` -- `search_agent.py:218`

**MEDIUM_RISK_UNTRACED tools (2):**
- `view_file` -- `question_answerer.py:297`
- `done_file_search` -- `question_answerer.py:501`

**LOW_RISK_UNTRACED tools (0):**
None.

---

## Coverage Gap Analysis

**Unresolved call edges:** 331
**Unique entrypoints traced to sensitive ops:** N/A (not reported in scan output)

331 unresolved call edges against 227 files gives a ratio of approximately 1.5 unresolved edges per file -- the lowest coverage gap ratio of the three systems evaluated, suggesting Sweep's codebase has comparatively more statically resolvable call paths. However, all three unclassified CEEs carry medium or high risk: `submit_task` at `search_agent.py:218` is HIGH_RISK_UNTRACED (the same tool name that produced WARNING findings from `question_answerer.py`, indicating the registration in `search_agent.py` has a distinct, unresolved path), and both `view_file` and `done_file_search` are MEDIUM_RISK_UNTRACED filesystem-adjacent operations whose full execution paths were not resolved.

---

## Key Findings Summary

1. Sweep is the only system in this evaluation with a CRITICAL finding: the `ripgrep` tool passes tool-controlled input directly into `subprocess.run` at `question_answerer.py:270` with no policy gate, creating a process execution vector reachable from crafted GitHub issue content.
2. All 15 classified findings are UNGOVERNED -- no policy gate was detected on any call path across the entire sweepai tool surface analyzed.
3. The `ask_question_about_codebase` tool (`search_agent.py:204`) appends tool-controlled input directly into `llm_state["questions_and_answers"]`, meaning adversarially crafted issue text can influence the LLM state store that coordinates all subsequent tool invocations including the subprocess-executing `ripgrep` tool.
4. Four sweepai tools (`semantic_search`, `vector_search`, `submit_task`, `add_files_to_context`) produce 13 WARNING-level STATE_MUTATION findings in `question_answerer.py`, accumulating file paths, content, and code snippet ranges into collections that feed downstream code-writing and PR-generation logic.
5. `submit_task` appears as both a WARNING-producing tool (via `question_answerer.py`) and a HIGH_RISK_UNTRACED unclassified CEE (via `search_agent.py:218`), indicating two distinct registration paths for the same tool -- one traced, one not -- which may represent an authorization bypass surface.
6. The combination of subprocess execution, LLM state mutation, and GitHub write access means a successful prompt injection via a crafted issue could traverse the full chain from issue text to `subprocess.run` argument to codebase modification without any policy gate intervention.
