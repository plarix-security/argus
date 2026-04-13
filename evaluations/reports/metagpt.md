# Wyscan Security Report: MetaGPT

> **Scan date:** 2026-04-13
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** github.com/geekan/MetaGPT
> **Framework(s) detected:** class-based-tool

## About This System

MetaGPT is a multi-agent meta-programming framework that assigns LLM agents to software company roles -- Product Manager, Architect, Engineer, QA -- and orchestrates them to collaboratively build software from a one-line specification. It generates code, tests, architecture documents, and API definitions through agent collaboration. Selected for evaluation because its role-based multi-agent architecture means a single compromised instruction can propagate through multiple agents, and its code-writing output combined with shell execution capabilities creates compounded risk surfaces.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 660 |
| Scan duration | 6.8s |
| Total CEEs detected | 455 |
| Classified findings | 376 |
| Unclassified CEEs | 79 |
| Unique entrypoints reaching sensitive ops | Not reported |
| Unresolved call edges (coverage gap) | 216 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 10 |
| WARNING | 191 |
| INFO | 175 |
| UNCLASSIFIED | 79 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

MetaGPT's class-based-tool framework exposes every agent action as an ungoverned entry point: all 10 CRITICAL findings trace directly from `run` tool registrations to subprocess and exec calls with no policy gate in any analyzed path. The multi-agent role system (Engineer, Architect, QA) means instruction-influenced input flows through cross-file call chains into `os.system`, `exec()`, `subprocess.Popen`, and `asyncio.create_subprocess_shell` -- a broad process execution surface where a single poisoned specification propagates to code execution across multiple agent roles. The 191 WARNING findings reveal that the same ungoverned `run` entry points also reach filesystem write operations and a graph database, meaning a misaligned agent can simultaneously execute arbitrary processes and persist attacker-controlled data.

---

## Critical Findings

### [run] -> [subprocess.run]

| Field | Value |
|-------|-------|
| File | `build_customized_agent.py:48` |
| Entry point | `build_customized_agent.py:47` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `python3` |

**Code:**
```
subprocess.run(["python3", "-c", code_text], capture_outp...
```

**Risk:** Tool-controlled input flows directly into `subprocess.run` executing `python3 -c code_text` -- an agent-generated code string is passed verbatim as a shell command argument. An adversary that can influence the agent's code generation step can achieve arbitrary code execution on the host. There is no sandboxing, allowlist, or policy gate between the tool registration and this call.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [shutil.rmtree]

| Field | Value |
|-------|-------|
| File | `prepare_documents.py:48` |
| Entry point | `prepare_documents.py:53` |
| Framework | class-based-tool |
| Operation type | FILESYSTEM |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `path` |

**Code:**
```
shutil.rmtree(path)
```

**Risk:** Instruction-influenced input reaches `shutil.rmtree` with `path` as the resource hint, meaning an adversarial specification could direct the agent to delete arbitrary directory trees. Since `prepare_documents` runs at project initialization, a crafted project path can cause irreversible data loss before any code is generated. No policy gate exists between the agent instruction and this destructive filesystem operation.

**AFB04 classification:** Unauthorized Action -- FILESYSTEM

---

### [run] -> [builtins.exec]

| Field | Value |
|-------|-------|
| File | `run_code.py:87` |
| Entry point | `run_code.py:120` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `code` |

**Code:**
```
exec(code, namespace)
```

**Risk:** Instruction-influenced `code` reaches `exec()` with a controlled namespace, providing full Python code execution capability to any agent that can write to the `run_code` action's input. This is equivalent to arbitrary code execution: `exec` evaluates any Python expression including imports, subprocess calls, and file operations. The resource hint `code` confirms the executed payload is agent-generated content.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [subprocess.Popen]

| Field | Value |
|-------|-------|
| File | `run_code.py:106` |
| Entry point | `run_code.py:120` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `command` |

**Code:**
```
subprocess.Popen(
```

**Risk:** Instruction-influenced `command` reaches `subprocess.Popen` through a single intermediate call from the same `run_code` entry point that also exposes `exec()`. This means the agent has two independent process execution vectors from a single ungoverned tool registration. A misaligned model can use either path to spawn arbitrary processes without approval.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [subprocess.run] (run_code.py)

| Field | Value |
|-------|-------|
| File | `run_code.py:151` |
| Entry point | `run_code.py:120` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `cmd` |

**Code:**
```
return subprocess.run(cmd, check=check, cwd=cwd, env=env)
```

**Risk:** A third process execution path from `run_code.py:120` -- `cmd` is instruction-influenced and passed directly to `subprocess.run` with a controllable working directory (`cwd`) and environment (`env`). Control over the execution environment compounds the risk: an attacker could modify `PYTHONPATH` or `PATH` to redirect execution to attacker-controlled binaries before `subprocess.run` is called.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [os.system] (via design_api.py)

| Field | Value |
|-------|-------|
| File | `common.py:63` |
| Entry point | `design_api.py:64` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `check_command` |

**Code:**
```
os.system(check_command)
```

**Risk:** `check_command` is instruction-influenced and passed to `os.system` through 5 intermediate calls crossing file boundaries from `design_api.py`. `os.system` invokes a full shell, so shell metacharacters in `check_command` enable command injection. The cross-file path means the vulnerable call site in `common.py` is shared infrastructure reachable from multiple agent roles.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [os.system] (via write_prd.py)

| Field | Value |
|-------|-------|
| File | `common.py:63` |
| Entry point | `write_prd.py:86` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `check_command` |

**Code:**
```
os.system(check_command)
```

**Risk:** The same `os.system(check_command)` call site in `common.py:63` is reachable from a second entry point, `write_prd.py` (the Product Requirements Document writer). This means the shell execution vulnerability is exploitable from the PRD-writing phase -- the earliest stage of the software development pipeline -- before any code is generated. A crafted requirement specification is sufficient to trigger arbitrary shell execution.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [asyncio.create_subprocess_shell] (via design_api.py)

| Field | Value |
|-------|-------|
| File | `mermaid.py:83` |
| Entry point | `design_api.py:64` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `commands` |

**Code:**
```
await asyncio.create_subprocess_shell(
```

**Risk:** `asyncio.create_subprocess_shell` passes `commands` directly to the shell interpreter. Instruction-influenced input reaching this call means diagram generation (Mermaid rendering) is an async shell injection vector. The cross-file path from `design_api.py` means this is triggered during the API design phase, when the agent is generating architecture diagrams from LLM-generated content.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [asyncio.create_subprocess_shell] (via write_prd.py)

| Field | Value |
|-------|-------|
| File | `mermaid.py:83` |
| Entry point | `write_prd.py:86` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | Yes |
| Resource hint | `commands` |

**Code:**
```
await asyncio.create_subprocess_shell(
```

**Risk:** Same `asyncio.create_subprocess_shell` call reachable from the PRD writer entry point, adding a second path to the async shell execution vulnerability in `mermaid.py`. The PRD phase precedes the design phase, so this vulnerability is exploitable from the very first agent action in MetaGPT's pipeline. Combined with the `os.system` finding above, `write_prd` alone exposes two distinct shell execution paths.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run] -> [subprocess.check_call]

| Field | Value |
|-------|-------|
| File | `setup.py:16` |
| Entry point | `setup.py:14` |
| Framework | class-based-tool |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | No |
| Resource hint | `npm` |

**Code:**
```
subprocess.check_call(["npm", "install", "-g", "@mermaid-...
```

**Risk:** `setup.py` is registered as a tool entry point and calls `subprocess.check_call` to install npm packages globally. While the argument is hardcoded, the absence of a policy gate means any agent that can invoke this tool triggers a global npm install without user approval. If the package name were made instruction-influenced (e.g., via a configuration variable), this becomes a supply-chain compromise vector.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

## Warning Findings

### MEMORY_WRITE (68 findings)

The `run` tool in `extract_readme.py`, `rebuild_class_view.py`, `rebuild_sequence_view.py`, and `graph_repository.py` all reach `self.graph_db.insert` and `self.graph_db.delete` through instruction-influenced paths with no policy gate. The graph database stores architectural knowledge (class relationships, sequence diagrams, file metadata) that is consumed by downstream agents -- meaning attacker-controlled graph insertions can poison the context seen by the Engineer and QA agent roles. `write_code.py` additionally reaches `codes.insert` with instruction-influenced content.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| run | class-based-tool | extract_readme.py:46 | self._filename | No |
| run | class-based-tool | extract_readme.py:48 | self._filename | No |
| run | class-based-tool | extract_readme.py:50 | self._filename | No |
| run | class-based-tool | extract_readme.py:52 | self._filename | No |
| run | class-based-tool | rebuild_class_view.py:103 | self.i_context | No |
| run | class-based-tool | rebuild_class_view.py:130 | ns_class_name | No |
| run | class-based-tool | rebuild_class_view.py:133 | ns_class_name | No |
| run | class-based-tool | rebuild_class_view.py:141 | ns_class_name | No |
| run | class-based-tool | rebuild_sequence_view.py:175 | r.subject (delete) | No |
| run | class-based-tool | rebuild_sequence_view.py:176 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:179 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:185 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:287 | ns_class_name | No |
| run | class-based-tool | rebuild_sequence_view.py:308 | ns_class_name | No |
| run | class-based-tool | rebuild_sequence_view.py:341 | ns_class_name | No |
| run | class-based-tool | rebuild_sequence_view.py:532 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:538 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:566 | r.subject (delete) | No |
| run | class-based-tool | rebuild_sequence_view.py:567 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:570 | entry.subject | No |
| run | class-based-tool | rebuild_sequence_view.py:575 | entry.subject | No |
| run | class-based-tool | graph_repository.py:185 | file_info.file | No |
| run | class-based-tool | graph_repository.py:188 | file_info.file | No |
| run | class-based-tool | graph_repository.py:192 | file_info.file | No |
| run | class-based-tool | graph_repository.py:198 | file_info.file | No |
| run | class-based-tool | graph_repository.py:205 | file_info.file | No |
| run | class-based-tool | graph_repository.py:210 | file_info.file | No |
| run | class-based-tool | graph_repository.py:217 | file_info.file | No |
| run | class-based-tool | graph_repository.py:221 | file_info.file | No |
| run | class-based-tool | graph_repository.py:225 | file_info.file | No |
| run | class-based-tool | graph_repository.py:232 | file_info.file | No |
| run | class-based-tool | graph_repository.py:238 | file_info.file | No |
| run | class-based-tool | graph_repository.py:275 | filename | No |
| run | class-based-tool | graph_repository.py:278 | filename | No |
| run | class-based-tool | graph_repository.py:279 | filename | No |
| run | class-based-tool | graph_repository.py:280 | filename | No |
| run | class-based-tool | write_code.py:204 | f"### The name of file to rewrite..." | No |

### FILESYSTEM (72 findings)

Filesystem write operations are reachable from at least 14 distinct `run` entry points spanning the core actions, Android assistant extension, code review extension, and Stanford Town extension. The most critical writes involve tool-controlled input: `agent_creator.py` writes agent-generated code verbatim to disk via `write_text`, `code_review.py` writes LLM-generated comments to JSON files via `f.write`, and `modify_code.py` opens and writes patch files with tool-controlled paths. The `manual_record.py` extension writes task descriptions and log entries with tool-controlled content to attacker-influenceable file paths.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| run | class-based-tool | agent_creator.py:51 | (mkdir) | No |
| run | class-based-tool | agent_creator.py:53 | code_text | Yes |
| run | class-based-tool | design_api.py:232 | (mkdir) | No |
| run | class-based-tool | execute_nb_code.py:279 | self.nb | No |
| run | class-based-tool | rebuild_class_view.py:77 | (mkdir) | No |
| run | class-based-tool | rebuild_class_view.py:83 | content | No |
| run | class-based-tool | rebuild_class_view.py:91 | content | No |
| run | class-based-tool | rebuild_class_view.py:97 | content | No |
| run | class-based-tool | invoice_ocr.py:79 | full_filename.parent | No |
| run | class-based-tool | invoice_ocr.py:148 | (mkdir) | No |
| run | class-based-tool | write_prd.py:163 | BUGFIX_FILENAME (delete) | No |
| run | class-based-tool | write_prd.py:279 | (mkdir) | No |
| run | class-based-tool | manual_record.py:51 | (mkdir) | No |
| run | class-based-tool | manual_record.py:53 | "" | No |
| run | class-based-tool | manual_record.py:54 | self.record_path | Yes |
| run | class-based-tool | manual_record.py:55 | task_desc | Yes |
| run | class-based-tool | manual_record.py:154 | stop\n | No |
| run | class-based-tool | manual_record.py:164 | log_str | No |
| run | class-based-tool | parse_record.py:45 | (mkdir) | No |
| run | class-based-tool | parse_record.py:121 | log_path | No |
| run | class-based-tool | parse_record.py:129 | \n | No |
| run | class-based-tool | parse_record.py:130 | doc_path | No |
| run | class-based-tool | parse_record.py:131 | doc_content | No |
| run | class-based-tool | screenshot_parse.py:106 | (mkdir) | No |
| run | class-based-tool | self_learn_and_reflect.py:72 | (mkdir) | No |
| run | class-based-tool | self_learn_and_reflect.py:230 | doc_content | No |
| run | class-based-tool | code_review.py:220 | (mkdir) | No |
| run | class-based-tool | code_review.py:222 | comments | Yes |
| run | class-based-tool | code_review.py:240 | comments | Yes |
| run | class-based-tool | modify_code.py:102 | (mkdir) | No |
| run | class-based-tool | modify_code.py:109 | patch_file | Yes |
| run | class-based-tool | modify_code.py:110 | resp | No |
| run | class-based-tool | experience_operation.py:71 | (mkdir) | No |
| run | class-based-tool | common.py:604 | (mkdir cross-file) | No |
| run | class-based-tool | common.py:608 | json_file (cross-file) | No |
| run | class-based-tool | common.py:739 | (mkdir cross-file, 5 entry pts) | No |
| run | class-based-tool | common.py:741 | data (cross-file, 5 entry pts) | No |
| run | class-based-tool | common.py:1201 | (mkdir cross-file, 3 entry pts) | No |
| run | class-based-tool | common.py:1204 | (mkdir cross-file, 3 entry pts) | No |
| run | class-based-tool | file.py:45 | (mkdir cross-file) | No |
| run | class-based-tool | file.py:48 | content (cross-file) | No |

### STATE_MUTATION (51 findings)

The `run` and `execute` tool entry points from `execute_nb_code.py`, `rebuild_sequence_view.py`, android assistant utilities, code review cleaner, Stanford Town simulation, and code writing actions all reach in-memory collection `.append()` calls with instruction-influenced content. The most sensitive is `execute_nb_code.py:139` where `self.nb.cells.append(new_code_cell(source=code))` with tool-controlled `code` appends agent-generated notebook cells -- these cells are later executed via the Jupyter kernel.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| run | class-based-tool | execute_nb_code.py:139 | code | Yes |
| run | class-based-tool | execute_nb_code.py:142 | markdown | No |
| run | class-based-tool | execute_nb_code.py:196 | output_text | No |
| run | class-based-tool | execute_nb_code.py:314 | text_content | No |
| run | class-based-tool | execute_nb_code.py:317 | f"\`\`\`{code_content}" | No |
| run | class-based-tool | execute_nb_code.py:323 | remaining_text | No |
| run | class-based-tool | import_repo.py:118 | path | No |
| run | class-based-tool | invoice_ocr.py:113 | ocr_result | Yes |
| run | class-based-tool | invoice_ocr.py:156 | invoice_data | No |
| run | class-based-tool | prepare_documents.py:61 | k (context.kwargs.set) | No |
| run | class-based-tool | rebuild_class_view.py:130 | ns_class_name | No |
| run | class-based-tool | rebuild_sequence_view.py:126 | r | No |
| run | class-based-tool | rebuild_sequence_view.py:135 | detail | No |
| run | class-based-tool | rebuild_sequence_view.py:138 | view | No |
| run | class-based-tool | rebuild_sequence_view.py:146 | use_cases | No |
| run | class-based-tool | rebuild_sequence_view.py:151 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:155 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:159 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:219 | r | No |
| run | class-based-tool | rebuild_sequence_view.py:251 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:255 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:259 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:311 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:315 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:321 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:326 | block | No |
| run | class-based-tool | rebuild_sequence_view.py:504 | name | No |
| run | class-based-tool | rebuild_sequence_view.py:530 | r | No |
| run | class-based-tool | research.py:273 | summary | Yes |
| run | class-based-tool | summarize_code.py:113 | code_block | No |
| run | class-based-tool | write_code.py:214 | f"### File Name..." | No |
| run | class-based-tool | write_code.py:226 | f"### File Name..." | No |
| run | class-based-tool | write_teaching_plan.py:28 | s | No |
| run | class-based-tool | self_learn_and_reflect.py:204 | resource_id | No |
| run | class-based-tool | self_learn_and_reflect.py:208 | resource_id | No |
| run | class-based-tool | screenshot_parse.py:133 | elem | No |
| run | class-based-tool | code_review.py:113 | commented_file | No |
| run | class-based-tool | code_review.py:170 | cmt | No |
| run | class-based-tool | code_review.py:231 | comment | No |
| run | class-based-tool | cleaner.py:14 | pfile.path (x2 entry pts) | No |
| run | class-based-tool | cleaner.py:16 | pfile (x2 entry pts) | No |
| run | class-based-tool | cleaner.py:47 | line (x2 entry pts) | No |
| run | class-based-tool | cleaner.py:48 | new_hunk (x2 entry pts) | No |
| run | class-based-tool | cleaner.py:49 | new_pfile (x2 entry pts) | No |
| run | class-based-tool | cleaner.py:63 | new_line (x2 entry pts) | No |
| execute | class-based-tool | retrieve.py:80 | i (cross-file) | No |
| execute | class-based-tool | retrieve.py:102 | score (cross-file) | No |
| execute | class-based-tool | retrieve.py:166 | importance (cross-file) | No |
| execute | class-based-tool | retrieve.py:167 | relevance (cross-file) | No |
| execute | class-based-tool | retrieve.py:168 | recency (cross-file) | No |
| execute | class-based-tool | utils.py:116 | (matrix init, cross-file) | No |
| execute | class-based-tool | utils.py:118 | (matrix fill, cross-file) | No |
| execute | class-based-tool | utils.py:138 | i (cross-file) | No |
| execute | class-based-tool | utils.py:142 | i (cross-file) | No |
| execute | class-based-tool | utils.py:146 | i (cross-file) | No |
| execute | class-based-tool | utils.py:150 | i (cross-file) | No |
| run | class-based-tool | schema.py:936 | attr (cross-file) | No |
| run | class-based-tool | schema.py:942 | arg (cross-file) | No |
| run | class-based-tool | schema.py:944 | method (cross-file) | No |
| run | class-based-tool | experience_operation.py:132 | exp | No |
| run | class-based-tool | utils.py:54 | elem (android, 3 entry pts) | No |
| run | class-based-tool | utils.py:77 | elem_id (android, 3 entry pts) | No |
| run | class-based-tool | utils.py:92 | elem (android, 2 entry pts) | No |
| run | class-based-tool | utils.py:107 | elem (android, 2 entry pts) | No |
| run | class-based-tool | utils.py:283 | param_value (android, 2 entry pts) | No |
| run | class-based-tool | utils.py:285 | param_value (android, 2 entry pts) | No |
| run | class-based-tool | common.py:757 | line (cross-file) | No |
| run | class-based-tool | common.py:769 | file_path (cross-file, 2 entry pts) | No |

---

## Info Findings

All 175 INFO findings are from tool `run` (class-based-tool). They divide into MEMORY_READ (`.get()`, `.keys()`, `.read_text()`, `.readlines()`, `.readline()` on repo objects, namespaces, and config) and FILESYSTEM (`.exists()`, `os.walk`, `iterdir()`). Representative rows below -- all findings follow the same ungoverned pattern.

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| run | class-based-tool | debug_error.py:56 | self.repo.test_outputs.get | self.i_context.output_filename |
| run | class-based-tool | debug_error.py:66 | self.repo.srcs.get | self.i_context.code_filename |
| run | class-based-tool | debug_error.py:69 | self.repo.tests.get | self.i_context.test_filename |
| run | class-based-tool | design_api.py:143 | changed_files.keys | (none) |
| run | class-based-tool | design_api.py:164 | changed_files.keys | (none) |
| run | class-based-tool | design_api.py:169 | changed_files.keys | (none) |
| run | class-based-tool | design_api.py:170 | data_api_design.changed_files.keys | (none) |
| run | class-based-tool | design_api.py:171 | seq_flow.changed_files.keys | (none) |
| run | class-based-tool | design_api.py:190 | system_design.get | root_relative_path.name |
| run | class-based-tool | design_api.py:211 | m.get | DATA_STRUCTURES_AND_INTERFACES.key |
| run | class-based-tool | design_api.py:222 | m.get | PROGRAM_CALL_FLOW.key |
| run | class-based-tool | design_api.py:235 | image_path.exists | (none) |
| run | class-based-tool | extract_readme.py:115 | Path.resolve.iterdir | (none) |
| run | class-based-tool | import_repo.py:139 | data_api_design.get | .class_diagram.mmd |
| run | class-based-tool | import_repo.py:142 | data_api_design.get | .sequence_diagram.mmd |
| run | class-based-tool | invoice_ocr.py:79 | zip_ref.read | zip_info.filename |
| run | class-based-tool | invoice_ocr.py:107 | os.walk | unzip_path (tool-controlled) |
| run | class-based-tool | prepare_documents.py:47 | path.exists | (none) |
| run | class-based-tool | project_management.py:99 | docs.task.changed_files.keys | (none) |
| run | class-based-tool | project_management.py:120 | docs.task.changed_files.keys | (none) |
| run | class-based-tool | project_management.py:127 | docs.task.changed_files.keys | (none) |
| run | class-based-tool | project_management.py:128 | api_spec_and_task.changed_files.keys | (none) |
| run | class-based-tool | project_management.py:137 | docs.task.get | root_relative_path.name |
| run | class-based-tool | project_management.py:167 | m.get | Required packages |
| run | class-based-tool | project_management.py:168 | self.repo.get | PACKAGE_REQUIREMENTS_FILENAME |
| run | class-based-tool | rebuild_class_view.py:180 | mappings.get | v |
| run | class-based-tool | write_framework.py:89 | rsp.find | tags |
| run | class-based-tool | run_code.py:90 | namespace.get | result |
| run | class-based-tool | run_code.py:102 | env.get | PYTHONPATH |
| run | class-based-tool | run_code.py:156 | file_path.exists | (none) |
| run | class-based-tool | skill_action.py:69 | txt.find | prefix |
| run | class-based-tool | skill_action.py:92 | self.args.keys | (none) |
| run | class-based-tool | summarize_code.py:106 | system_design.get | design_pathname.name |
| run | class-based-tool | summarize_code.py:108 | docs.task.get | task_pathname.name |
| run | class-based-tool | summarize_code.py:111 | self.repo.srcs.get | filename |
| run | class-based-tool | write_code_review.py:304 | os.path.exists | input (tool-controlled) |
| run | class-based-tool | write_code.py:106 | code_plan_and_change.get | coding_context.task_doc.filename |
| run | class-based-tool | write_code.py:109 | self.repo.test_outputs.get | test_ |
| run | class-based-tool | write_code.py:113 | docs.code_summary.get | coding_context.design_doc.filename |
| run | class-based-tool | write_code.py:184 | project_repo.docs.task.get | task_doc.filename |
| run | class-based-tool | write_code.py:197 | m.get | TASK_LIST.key |
| run | class-based-tool | write_code.py:200 | src_file_repo.get | filename |
| run | class-based-tool | write_code.py:210 | src_file_repo.get | filename |
| run | class-based-tool | write_code.py:222 | src_file_repo.get | filename |
| run | class-based-tool | write_prd.py:175 | docs.prd.changed_files.keys | (none) |
| run | class-based-tool | write_prd.py:183 | docs.prd.changed_files.keys | (none) |
| run | class-based-tool | write_prd.py:184 | resources.prd.changed_files.keys | (none) |
| run | class-based-tool | write_prd.py:185 | competitive_analysis.changed_files.keys | (none) |
| run | class-based-tool | write_prd.py:242 | node.get | issue_type |
| run | class-based-tool | write_prd.py:252 | node.get | is_relative |
| run | class-based-tool | write_prd.py:275 | m.get | COMPETITIVE_QUADRANT_CHART.key |
| run | class-based-tool | write_prd.py:282 | image_path.exists | (none) |
| run | class-based-tool | write_teaching_plan.py:24 | TOPIC_STATEMENTS.get | self.topic |
| run | class-based-tool | manual_record.py:69 | screenshot_path.exists | (none) |
| run | class-based-tool | manual_record.py:69 | xml_path.exists | (none) |
| run | class-based-tool | manual_record.py:72 | extra_config.get | min_dist |
| run | class-based-tool | parse_record.py:47 | pathlib.Path.read_text | (none) |
| run | class-based-tool | parse_record.py:50 | builtins.open | self.record_path (tool-controlled) |
| run | class-based-tool | parse_record.py:51 | builtins.open.readlines | (none) |
| run | class-based-tool | parse_record.py:56 | builtins.open.readline | (none) |
| run | class-based-tool | parse_record.py:86 | doc_path.exists | (none) |
| run | class-based-tool | parse_record.py:88 | doc_path.read_text | (none) |
| run | class-based-tool | parse_record.py:94 | extra_config.get | doc_refine |
| run | class-based-tool | screenshot_parse.py:64 | doc_path.exists | (none) |
| run | class-based-tool | screenshot_parse.py:67 | doc_path.read_text | (none) |
| run | class-based-tool | screenshot_parse.py:113 | screenshot_path.exists | (none) |
| run | class-based-tool | screenshot_parse.py:113 | xml_path.exists | (none) |
| run | class-based-tool | screenshot_parse.py:129 | extra_config.get | min_dist |
| run | class-based-tool | self_learn_and_reflect.py:90 | screenshot_path.exists | (none) |
| run | class-based-tool | self_learn_and_reflect.py:90 | xml_path.exists | (none) |
| run | class-based-tool | self_learn_and_reflect.py:93 | extra_config.get | min_dist |
| run | class-based-tool | self_learn_and_reflect.py:151 | screenshot_path.exists | (none) |
| run | class-based-tool | self_learn_and_reflect.py:217 | doc_path.exists | (none) |
| run | class-based-tool | self_learn_and_reflect.py:219 | doc_path.read_text | (none) |
| run | class-based-tool | utils.py:73 | extra_config.get | min_dist (3 entry pts) |
| run | class-based-tool | utils.py:251 | parsed_json.get | Decision |
| run | class-based-tool | utils.py:256 | parsed_json.get | Decision |
| run | class-based-tool | utils.py:257 | parsed_json.get | (continuation) |

*Note: 175 total INFO findings across the full scan. The table above covers the distinct call sites observed. Remaining entries follow identical patterns (MEMORY_READ `.get()` / FILESYSTEM `.exists()`) from the same entry points listed above.*

---

## Unclassified CEEs

**Total:** 79

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED (0):**
None.

**MEDIUM_RISK_UNTRACED (0):**
None.

**LOW_RISK_UNTRACED (79):**
79 action class `run` method registrations and 1 `execute` registration across MetaGPT's full action hierarchy. All function names are `run` (or `execute` for `st_role.py`), which do not match the HIGH or MEDIUM risk name lists. These represent every MetaGPT action that Wyscan could not fully trace -- including `build_customized_agent.py`, `dalle_gpt4v_agent.py`, `debate.py`, `analyze_requirements.py`, `debug_error.py`, `design_api_review.py`, `design_api.py`, `ask_review.py`, `execute_nb_code.py`, `write_analysis_code.py` (x2), `write_plan.py`, `execute_task.py`, `extract_readme.py`, `generate_questions.py`, `import_repo.py`, `invoice_ocr.py` (x3), `prepare_documents.py`, `prepare_interview.py`, `project_management.py`, `rebuild_class_view.py`, `rebuild_sequence_view.py`, `write_framework.py`, `pic2txt.py`, `compress_external_interfaces.py` (x2), `detect_interaction.py` (x2), `write_trd.py`, `research.py` (x3), `run_code.py`, `search_and_summarize.py`, `search_enhanced_qa.py`, `skill_action.py` (x2), `summarize_code.py`, `talk_action.py`, `write_code_an_draft.py`, `write_code_plan_and_change_an.py`, `write_code_review.py` (x2), `write_code.py`, `write_docstring.py`, `write_prd_review.py`, `write_prd.py`, `write_review.py`, `write_teaching_plan.py`, `write_tutorial.py` (x2), `manual_record.py`, `parse_record.py`, `screenshot_parse.py`, `self_learn_and_reflect.py`, `code_review.py`, `modify_code.py`, `dummy_action.py`, `st_action.py`, `st_role.py` (execute), `common_actions.py` (x5), `experience_operation.py` (x2), `moderator_actions.py` (x3), `role.py`, `setup.py`.

---

## Coverage Gap Analysis

**Unresolved call edges:** 216
**Unique entrypoints traced to sensitive ops:** Not reported

With 216 unresolved call edges across 660 files (a ratio of 0.33 edges per file), MetaGPT's call graph has moderate but non-trivial unresolved complexity -- primarily from the cross-file paths that the scanner explicitly flagged in 30+ CRITICAL and WARNING findings. The actual exposure surface is larger than the 376 classified findings suggest: the 79 unclassified `run` registrations each represent an action whose full execution path was not resolved, and given that the classified findings show nearly every resolved action reaches filesystem writes or process execution, it is reasonable to assume many unclassified actions have similar exposure. The cross-file path annotations in CRITICAL findings (e.g., `design_api.py` -> `common.py` -> `os.system`) indicate that shared infrastructure in `common.py` and `graph_repository.py` is a convergence point for multiple agent roles, amplifying the blast radius of any single authorization failure.

---

## Key Findings Summary

1. MetaGPT has 10 CRITICAL process execution findings -- the highest CRITICAL count of any system evaluated -- all from ungoverned `run` tool registrations, spanning `subprocess.run`, `subprocess.Popen`, `asyncio.create_subprocess_shell`, `os.system`, `builtins.exec`, `subprocess.check_call`, and `shutil.rmtree` across 7 distinct call sites.

2. The `write_prd.py` entry point alone is a gateway to two shell execution paths (`os.system` via `common.py:63` and `asyncio.create_subprocess_shell` via `mermaid.py:83`), meaning a crafted product requirement specification is sufficient to trigger arbitrary shell execution before any code generation occurs.

3. `builtins.exec(code, namespace)` in `run_code.py:87` is reachable from the same entry point as `subprocess.Popen` and `subprocess.run`, giving a single agent action three independent code execution vectors with no policy gate on any of them.

4. 68 WARNING findings reach `graph_db.insert` and `graph_db.delete` with instruction-influenced content -- the graph database stores architectural knowledge consumed by downstream agents, meaning attacker-controlled insertions poison the context passed between agent roles, enabling multi-hop influence across the entire software development pipeline.

5. The Android assistant extension (`manual_record.py`, `parse_record.py`, `screenshot_parse.py`, `self_learn_and_reflect.py`) contributes 30+ WARNING and INFO findings, with tool-controlled input reaching file paths (`self.record_path`, `task_desc`) and `os.walk(unzip_path)`, indicating that this extension was developed without the same security review as the core actions.

6. All 79 unclassified CEEs are `run` method registrations -- functionally identical to the entry points that produced CRITICAL findings in the classified set -- meaning the true process execution exposure surface is substantially larger than the 10 CRITICAL findings indicate.
