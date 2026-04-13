# Wyscan Security Report: AutoGPT

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** github.com/Significant-Gravitas/AutoGPT
> **Framework(s) detected:** langchain, export-entry

## About This System

AutoGPT is the original autonomous GPT-4 agent that pioneered recursive task decomposition and self-directed execution loops. It maintains persistent memory, can execute shell commands, browse the web, write and read files, and interact with external APIs without continuous human oversight. Selected for evaluation because it established the blueprint for autonomous AI agents and remains one of the most widely forked repositories in AI, making its security posture broadly influential across derivative systems.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 1735 |
| Scan duration | 95.5s |
| Total CEEs detected | 556 |
| Classified findings | 367 |
| Unclassified CEEs | 189 |
| Unique entrypoints reaching sensitive ops | 123 |
| Unresolved call edges (coverage gap) | 7432 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| WARNING | 92 |
| INFO | 272 |
| UNCLASSIFIED | 189 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

All 367 classified findings across the AutoGPT platform backend and frontend emit "No policy gate detected in the analyzed call path," meaning every reachable operation -- from subprocess execution to filesystem writes to network fetches -- is accessible to the langchain `_execute` tool without authorization checks. The scan detected two frameworks (langchain for the Python backend copilot layer, export-entry for the TypeScript frontend direct-upload path), with tool-controlled input confirmed flowing into subprocess arguments in the highest-severity sandbox execution path. The breadth of reachable operations -- including `asyncio.create_subprocess_exec`, `os.unlink`, `sandbox.files.write`, `os.makedirs`, `aiohttp.ClientSession.get`, and `builtins.open` for both read and write -- reflects the system's intentional design as a fully autonomous agent, which makes the absence of any authorization layer a structural rather than incidental risk.

---

## Critical Findings

### [_execute] -> [PROCESS_EXECUTION]

| Field | Value |
|-------|-------|
| File | `agent_browser.py:87` |
| Entry point | `agent_browser.py:449` |
| Framework | langchain |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | No |
| Resource hint | `cmd` |

**Code:**
```
await asyncio.create_subprocess_exec(
```

**Risk:** The `_execute` tool in the agent browser reaches `asyncio.create_subprocess_exec` through 3 intermediate calls with no policy gate. The resource hint `cmd` indicates the command argument is derived from browser tool state, enabling arbitrary subprocess spawning from the browser automation layer. Any LLM-directed browser action that reaches this path can execute system commands without authorization.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [_execute] -> [FILESYSTEM]

| Field | Value |
|-------|-------|
| File | `agent_browser.py:833` |
| Entry point | `agent_browser.py:784` |
| Framework | langchain |
| Operation type | FILESYSTEM |
| Tool-controlled input | No |
| Instruction-influenced | No |
| Resource hint | `tmp_path` |

**Code:**
```
os.unlink(tmp_path)
```

**Risk:** The `_execute` tool reaches `os.unlink` with `tmp_path` as the target, enabling deletion of arbitrary files in the temporary path context with no policy gate. Although scoped to `tmp_path`, the absence of authorization means the agent can autonomously delete files created during browser sessions. This is reachable from the same browser tool entry point (`agent_browser.py:784`) that also constructs subprocess command arguments.

**AFB04 classification:** Unauthorized Action -- FILESYSTEM

---

### [_execute] -> [PROCESS_EXECUTION]

| Field | Value |
|-------|-------|
| File | `sandbox.py:243` |
| Entry point | `bash_exec.py:78` |
| Framework | langchain |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `full_command` |

**Code:**
```
await asyncio.create_subprocess_exec(
```

**Risk:** This is the most severe finding: tool-controlled input is traced directly into the `asyncio.create_subprocess_exec` arguments, with `full_command` as the resource hint. The path crosses file boundaries (bash_exec.py -> sandbox.py) through only 1 intermediate call, meaning the LLM-supplied command string reaches subprocess execution with minimal indirection and no authorization gate. This represents a direct command injection surface where any instruction that influences `full_command` becomes an arbitrary code execution primitive.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

## Warning Findings

### STATE_MUTATION (83 findings)

The dominant warning pattern is unbounded `.append()` and `.set()` calls on in-memory collections -- agent lists, node lists, link lists, output buffers, missing-field lists, credential lists, and execution task holders -- all reachable from the `_execute` tool (langchain) without policy gates. These mutations affect agent graph construction (`create_agent.py`, `customize_agent.py`, `edit_agent.py`), agent search results (`find_agent.py`, `find_library_agent.py`), block execution output accumulation (`run_block.py`, `continue_run_block.py`), and async execution state (`agent_output.py`, `run_agent.py`). Approximately 40 of these findings carry instruction-influenced input and 8 carry tool-controlled input, meaning LLM output directly shapes in-memory agent state with no authorization boundary.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute | langchain | `db.py:1485` | `n.id` | No |
| _execute | langchain | `helpers.py:55` | `text` | No |
| _execute | langchain | `helpers.py:57` | `text` | No |
| _execute | langchain | `helpers.py:59` | `image` | No |
| _execute | langchain | `helpers.py:67` | `resource` | No |
| _execute | langchain | `file_ref.py:258` | `text` | No |
| _execute | langchain | `file_ref.py:265` | `f"[file-ref error: {msg}]"` | No |
| _execute | langchain | `file_ref.py:272` | `f"[file-ref error: {msg}]"` | No |
| _execute | langchain | `file_ref.py:289` | `content` | No |
| _execute | langchain | `file_ref.py:294` | `f"[file-ref error: {exc}]"` | No |
| _execute | langchain | `file_ref.py:297` | `text` | No |
| _execute | langchain | `agent_browser.py:816` | `--annotate` | No |
| _execute | langchain | `agent_browser.py:817` | `tmp_path` | No |
| _execute | langchain | `blocks.py:56` | `info` | No |
| _execute | langchain | `blocks.py:56` | `info` | No |
| _execute | langchain | `blocks.py:56` | `info` | No |
| _execute | langchain | `core.py:175` | `agent` | Yes |
| _execute | langchain | `core.py:175` | `agent` | Yes |
| _execute | langchain | `core.py:175` | `agent` | Yes |
| _execute | langchain | `core.py:551` | `node` | No |
| _execute | langchain | `core.py:551` | `node` | No |
| _execute | langchain | `core.py:551` | `node` | No |
| _execute | langchain | `core.py:562` | `source_id` | No |
| _execute | langchain | `core.py:562` | `source_id` | No |
| _execute | langchain | `core.py:562` | `source_id` | No |
| _execute | langchain | `core.py:564` | `sink_id` | No |
| _execute | langchain | `core.py:564` | `sink_id` | No |
| _execute | langchain | `core.py:564` | `sink_id` | No |
| _execute | langchain | `core.py:566` | `source_name` | No |
| _execute | langchain | `core.py:566` | `source_name` | No |
| _execute | langchain | `core.py:566` | `source_name` | No |
| _execute | langchain | `core.py:568` | `sink_name` | No |
| _execute | langchain | `core.py:568` | `sink_name` | No |
| _execute | langchain | `core.py:568` | `sink_name` | No |
| _execute | langchain | `core.py:584` | `link` | No |
| _execute | langchain | `core.py:584` | `link` | No |
| _execute | langchain | `core.py:584` | `link` | No |
| _execute | langchain | `pipeline.py:138` | `'name'` | No |
| _execute | langchain | `pipeline.py:138` | `'name'` | No |
| _execute | langchain | `pipeline.py:138` | `'name'` | No |
| _execute | langchain | `pipeline.py:140` | `'description'` | No |
| _execute | langchain | `pipeline.py:140` | `'description'` | No |
| _execute | langchain | `pipeline.py:140` | `'description'` | No |
| _execute | langchain | `agent_search.py:63` | `agent_info` | No |
| _execute | langchain | `agent_search.py:63` | `agent_info` | No |
| _execute | langchain | `agent_search.py:69` | `agent` | No |
| _execute | langchain | `agent_search.py:69` | `agent` | No |
| _execute | langchain | `agent_search.py:133` | `agent` | Yes |
| _execute | langchain | `agent_search.py:133` | `agent` | Yes |
| _execute | langchain | `agent_search.py:146` | `agent` | Yes |
| _execute | langchain | `agent_search.py:146` | `agent` | Yes |
| _execute | langchain | `connect_integration.py:160` | `s` | No |
| _execute | langchain | `connect_integration.py:167` | `reason` | Yes |
| _execute | langchain | `execution_utils.py:157` | _(none)_ | No |
| _execute | langchain | `execution_utils.py:157` | _(none)_ | No |
| _execute | langchain | `execution_utils.py:161` | _(none)_ | No |
| _execute | langchain | `execution_utils.py:161` | _(none)_ | No |
| _execute | langchain | `execution_utils.py:164` | `consume_task` | No |
| _execute | langchain | `execution_utils.py:164` | `consume_task` | No |
| _execute | langchain | `find_block.py:250` | `summary` | No |
| _execute | langchain | `helpers.py:84` | `entry` | No |
| _execute | langchain | `helpers.py:84` | `entry` | No |
| _execute | langchain | `helpers.py:118` | `output_data` | No |
| _execute | langchain | `helpers.py:118` | `output_data` | No |
| _execute | langchain | `helpers.py:215` | `input_data` | Yes |
| _execute | langchain | `helpers.py:215` | `input_data` | Yes |
| _execute | langchain | `helpers.py:219` | `output_data` | No |
| _execute | langchain | `helpers.py:219` | `output_data` | No |
| _execute | langchain | `run_agent.py:334` | `f"Required: ..."` | No |
| _execute | langchain | `run_agent.py:336` | `f"Optional (have defaults): ..."` | No |
| _execute | langchain | `run_agent.py:341` | `suffix` | No |
| _execute | langchain | `search_docs.py:178` | `doc_title` | No |
| _execute | langchain | `utils.py:101` | `title` | No |
| _execute | langchain | `utils.py:292` | `f"{field_name} (validation failed: {e})"` | No |
| _execute | langchain | `utils.py:292` | `f"{field_name} (validation failed: {e})"` | No |
| _execute | langchain | `utils.py:303` | `field_name` | No |
| _execute | langchain | `utils.py:303` | `field_name` | No |
| _execute | langchain | `utils.py:433` | `f"{credential_field_name} (validation failed: {e})"` | No |
| _execute | langchain | `utils.py:443` | `f"scopes including {list(...)}"` | No |
| _execute | langchain | `utils.py:446` | `f"{credential_field_name} (requires ...)"` | No |
| _execute | langchain | `workspace_files.py:490` | `f"  - {f.path} ..."` | No |
| _execute | langchain | `workspace_files.py:492` | `f"  ... and {total - len(files)} more"` | No |
| _execute | langchain | `workspace_files.py:493` | `f"Total size: {total_size:,} bytes"` | No |
| _execute | langchain | `simulator.py:94` | `f"- {pin_name}: {pin_type} ({req})"` | No |
| _execute | langchain | `simulator.py:94` | `f"- {pin_name}: {pin_type} ({req})"` | No |

---

### FILESYSTEM (5 findings)

Five warnings trace the `_execute` tool to direct filesystem write operations: two `os.makedirs` calls (in `sandbox.py` and `workspace_files.py`), a `sandbox.files.write` call, and two `builtins.open` calls in write mode. Four of these five carry tool-controlled or instruction-influenced input, meaning the file paths and contents are derived from LLM-supplied data. The `workspace_files.py` cluster is particularly significant as it handles both the sandbox remote path and a local validated path with no policy gate.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute | langchain | `sandbox.py:80` | `workspace` | Yes |
| _execute | langchain | `workspace_files.py:163` | `remote` | Yes |
| _execute | langchain | `workspace_files.py:179` | `dir_path` | Yes |
| _execute | langchain | `workspace_files.py:180` | `validated` | Yes |
| _execute | langchain | `workspace_files.py:181` | `content` | No |

---

### NETWORK (2 findings)

Two warnings trace network calls reachable from `_execute`: an `aiohttp.ClientSession.get` to `https://api.github.com/user` (GitHub identity lookup, cross-file from `bash_exec.py:78`) and a `fetch` call in the TypeScript direct-upload path (`direct-upload.ts:36`, framework: export-entry). Neither has a policy gate detected.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute | langchain | `integration_creds.py:230` | `https://api.github.com/user` | No |
| uploadFileDirect | export-entry | `direct-upload.ts:36` | _(none)_ | No |

---

### PROCESS_EXECUTION (2 findings)

Two warnings trace `.append()` calls that build subprocess command argument arrays (`cmd_args`) in `agent_browser.py`. These are warning-level because they append to the command argument list rather than directly invoking the subprocess, but they feed directly into the CRITICAL subprocess execution finding at `agent_browser.py:87`. No policy gate is detected on either path.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute | langchain | `agent_browser.py:816` | `--annotate` | No |
| _execute | langchain | `agent_browser.py:817` | `tmp_path` | No |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| _execute | langchain | `__init__.py:131` | MEMORY_READ (get_blocks().get) | `block_id` |
| _execute | langchain | `__init__.py:131` | MEMORY_READ (get_blocks().get) | `block_id` |
| _execute | langchain | `__init__.py:131` | MEMORY_READ (get_blocks().get) | `block_id` |
| _execute | langchain | `helpers.py:51` | MEMORY_READ (item.get) | `type` |
| _execute | langchain | `helpers.py:53` | MEMORY_READ (item.get) | `text` |
| _execute | langchain | `helpers.py:62` | MEMORY_READ (item.get) | `data` |
| _execute | langchain | `helpers.py:63` | MEMORY_READ (item.get) | `mimeType` |
| _execute | langchain | `helpers.py:67` | MEMORY_READ (item.get) | `resource` |
| _execute | langchain | `helpers.py:104` | MEMORY_READ ((cred.metadata or {}).get) | `mcp_server_url` |
| _execute | langchain | `context.py:93` | MEMORY_READ (_current_permissions.get) | _(none)_ |
| _execute | langchain | `context.py:93` | MEMORY_READ (_current_permissions.get) | _(none)_ |
| _execute | langchain | `context.py:98` | MEMORY_READ (_current_sandbox.get) | _(none)_ |
| _execute | langchain | `context.py:98` | MEMORY_READ (_current_sandbox.get) | _(none)_ |
| _execute | langchain | `context.py:98` | MEMORY_READ (_current_sandbox.get) | _(none)_ |
| _execute | langchain | `context.py:103` | MEMORY_READ (_current_sdk_cwd.get) | _(none)_ |
| _execute | langchain | `context.py:103` | MEMORY_READ (_current_sdk_cwd.get) | _(none)_ |
| _execute | langchain | `context.py:172` | MEMORY_READ (_current_project_dir.get) | `""` |
| _execute | langchain | `context.py:172` | MEMORY_READ (_current_project_dir.get) | `""` |
| _execute | langchain | `integration_creds.py:121` | MEMORY_READ (_token_cache.get) | `cache_key` |
| _execute | langchain | `integration_creds.py:218` | IDENTITY (_gh_identity_cache.get) | `user_id` |
| _execute | langchain | `integration_creds.py:254` | IDENTITY (data.get) | `name` |
| _execute | langchain | `integration_creds.py:257` | IDENTITY (data.get) | `email` |
| _execute | langchain | `integration_creds.py:259` | IDENTITY (data.get) | `id` |
| _execute | langchain | `integration_creds.py:260` | IDENTITY (data.get) | `login` |
| _execute | langchain | `file_ref.py:167` | FILESYSTEM (builtins.open) | `resolved` |
| _execute | langchain | `file_ref.py:168` | FILESYSTEM (builtins.open.read) | `_MAX_BARE_REF_BYTES` |
| _execute | langchain | `file_ref.py:189` | FILESYSTEM (sandbox.files.read) | `remote` |
| _execute | langchain | `file_ref.py:337` | MEMORY_READ ((input_schema or {}).get) | `properties` |
| _execute | langchain | `file_ref.py:379` | MEMORY_READ (prop_schema.get) | `type` |
| _execute | langchain | `file_ref.py:383` | MEMORY_READ ((prop_schema or {}).get) | `properties` |
| _execute | langchain | `file_ref.py:385` | MEMORY_READ (nested_props.get) | `k` |
| _execute | langchain | `file_ref.py:389` | MEMORY_READ ((prop_schema or {}).get) | `items` |
| _execute | langchain | `file_ref.py:393` | MEMORY_READ (properties.get) | `k` |
| _execute | langchain | `file_ref.py:488` | MEMORY_READ (MIME_TO_FORMAT.get) | `mime` |
| _execute | langchain | `file_ref.py:509` | MEMORY_READ (prop_schema.get) | `type` |
| _execute | langchain | `file_ref.py:510` | MEMORY_READ (prop_schema.get) | `format` |
| _execute | langchain | `file_ref.py:565` | MEMORY_READ ((prop_schema or {}).get) | `type` |
| _execute | langchain | `file_ref.py:613` | MEMORY_READ (prop_schema.get) | `type` |
| _execute | langchain | `file_ref.py:641` | MEMORY_READ ((prop_schema.get("items") or {}).get) | `type` |
| _execute | langchain | `file_ref.py:641` | MEMORY_READ (prop_schema.get) | `items` |
| _execute | langchain | `add_understanding.py:84` | MEMORY_READ (BusinessUnderstandingInput.model_fields.keys) | _(none)_ |
| _execute | langchain | `agent_browser.py:234` | MEMORY_READ (state.get) | `url` |
| _execute | langchain | `agent_browser.py:235` | MEMORY_READ (state.get) | `cookies` |
| _execute | langchain | `agent_browser.py:236` | MEMORY_READ (state.get) | `local_storage` |
| _execute | langchain | `agent_browser.py:274` | MEMORY_READ (c.get) | `name` |
| _execute | langchain | `agent_browser.py:275` | MEMORY_READ (c.get) | `value` |
| _execute | langchain | `agent_browser.py:276` | MEMORY_READ (c.get) | `domain` |
| _execute | langchain | `agent_browser.py:277` | MEMORY_READ (c.get) | `path` |
| _execute | langchain | `agent_browser.py:828` | FILESYSTEM (builtins.open) | `tmp_path` |
| _execute | langchain | `agent_browser.py:829` | FILESYSTEM (builtins.open.read) | _(none)_ |
| _execute | langchain | `core.py:538` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `core.py:538` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `core.py:538` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `core.py:539` | MEMORY_READ (n.get) | `block_id` |
| _execute | langchain | `core.py:539` | MEMORY_READ (n.get) | `block_id` |
| _execute | langchain | `core.py:539` | MEMORY_READ (n.get) | `block_id` |
| _execute | langchain | `core.py:541` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:541` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:541` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:546` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:546` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:546` | MEMORY_READ (n.get) | `id` |
| _execute | langchain | `core.py:548` | MEMORY_READ (n.get) | `input_default` |
| _execute | langchain | `core.py:548` | MEMORY_READ (n.get) | `input_default` |
| _execute | langchain | `core.py:548` | MEMORY_READ (n.get) | `input_default` |
| _execute | langchain | `core.py:549` | MEMORY_READ (n.get) | `metadata` |
| _execute | langchain | `core.py:549` | MEMORY_READ (n.get) | `metadata` |
| _execute | langchain | `core.py:549` | MEMORY_READ (n.get) | `metadata` |
| _execute | langchain | `core.py:554` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `core.py:554` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `core.py:554` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `core.py:555` | MEMORY_READ (link_data.get) | `source_id` |
| _execute | langchain | `core.py:555` | MEMORY_READ (link_data.get) | `source_id` |
| _execute | langchain | `core.py:555` | MEMORY_READ (link_data.get) | `source_id` |
| _execute | langchain | `core.py:556` | MEMORY_READ (link_data.get) | `sink_id` |
| _execute | langchain | `core.py:556` | MEMORY_READ (link_data.get) | `sink_id` |
| _execute | langchain | `core.py:556` | MEMORY_READ (link_data.get) | `sink_id` |
| _execute | langchain | `core.py:557` | MEMORY_READ (link_data.get) | `source_name` |
| _execute | langchain | `core.py:557` | MEMORY_READ (link_data.get) | `source_name` |
| _execute | langchain | `core.py:557` | MEMORY_READ (link_data.get) | `source_name` |
| _execute | langchain | `core.py:558` | MEMORY_READ (link_data.get) | `sink_name` |
| _execute | langchain | `core.py:558` | MEMORY_READ (link_data.get) | `sink_name` |
| _execute | langchain | `core.py:558` | MEMORY_READ (link_data.get) | `sink_name` |
| _execute | langchain | `core.py:571` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:571` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:571` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:577` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:577` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:577` | MEMORY_READ (link_data.get) | `id` |
| _execute | langchain | `core.py:582` | MEMORY_READ (link_data.get) | `is_static` |
| _execute | langchain | `core.py:582` | MEMORY_READ (link_data.get) | `is_static` |
| _execute | langchain | `core.py:582` | MEMORY_READ (link_data.get) | `is_static` |
| _execute | langchain | `core.py:587` | MEMORY_READ (agent_json.get) | `id` |
| _execute | langchain | `core.py:587` | MEMORY_READ (agent_json.get) | `id` |
| _execute | langchain | `core.py:587` | MEMORY_READ (agent_json.get) | `id` |
| _execute | langchain | `core.py:588` | MEMORY_READ (agent_json.get) | `version` |
| _execute | langchain | `core.py:588` | MEMORY_READ (agent_json.get) | `version` |
| _execute | langchain | `core.py:588` | MEMORY_READ (agent_json.get) | `version` |
| _execute | langchain | `core.py:589` | MEMORY_READ (agent_json.get) | `is_active` |
| _execute | langchain | `core.py:589` | MEMORY_READ (agent_json.get) | `is_active` |
| _execute | langchain | `core.py:589` | MEMORY_READ (agent_json.get) | `is_active` |
| _execute | langchain | `core.py:590` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `core.py:590` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `core.py:590` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `core.py:591` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `core.py:591` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `core.py:591` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `pipeline.py:122` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `pipeline.py:122` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `pipeline.py:122` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `pipeline.py:123` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `pipeline.py:123` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `pipeline.py:123` | MEMORY_READ (agent_json.get) | `description` |
| _execute | langchain | `pipeline.py:124` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `pipeline.py:124` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `pipeline.py:124` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `pipeline.py:125` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `pipeline.py:125` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `pipeline.py:125` | MEMORY_READ (agent_json.get) | `links` |
| _execute | langchain | `pipeline.py:137` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `pipeline.py:137` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `pipeline.py:137` | MEMORY_READ (agent_json.get) | `name` |
| _execute | langchain | `ask_question.py:71` | MEMORY_READ (kwargs.get) | `question` |
| _execute | langchain | `ask_question.py:75` | MEMORY_READ (kwargs.get) | `options` |
| _execute | langchain | `ask_question.py:79` | MEMORY_READ (kwargs.get) | `keyword` |
| _execute | langchain | `connect_integration.py:140` | MEMORY_READ (SUPPORTED_PROVIDERS.get) | `provider` |
| _execute | langchain | `continue_run_block.py:74` | MEMORY_READ (reviews.get) | `review_id` |
| _execute | langchain | `create_agent.py:86` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `customize_agent.py:84` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `edit_agent.py:92` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `edit_agent.py:109` | MEMORY_READ (current_agent.get) | `id` |
| _execute | langchain | `edit_agent.py:110` | MEMORY_READ (current_agent.get) | `version` |
| _execute | langchain | `feature_requests.py:186` | MEMORY_READ (data.get("searchIssues").get) | `nodes` |
| _execute | langchain | `feature_requests.py:186` | MEMORY_READ (data.get) | `searchIssues` |
| _execute | langchain | `feature_requests.py:283` | MEMORY_READ (data.get) | `customerUpsert` |
| _execute | langchain | `feature_requests.py:284` | MEMORY_READ (result.get) | `success` |
| _execute | langchain | `feature_requests.py:370` | MEMORY_READ (data.get) | `issueCreate` |
| _execute | langchain | `feature_requests.py:371` | MEMORY_READ (result.get) | `success` |
| _execute | langchain | `feature_requests.py:379` | MEMORY_READ (issue.get) | `identifier` |
| _execute | langchain | `feature_requests.py:402` | MEMORY_READ (data.get) | `customerNeedCreate` |
| _execute | langchain | `feature_requests.py:403` | MEMORY_READ (need_result.get) | `success` |
| _execute | langchain | `feature_requests.py:439` | MEMORY_READ (issue_info.get) | `url` |
| _execute | langchain | `fix_agent.py:66` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `get_agent_building_guide.py:21` | FILESYSTEM (pathlib.Path.read_text) | `utf-8` |
| _execute | langchain | `get_doc_page.py:106` | FILESYSTEM (full_path.exists) | _(none)_ |
| _execute | langchain | `get_doc_page.py:124` | FILESYSTEM (pathlib.Path.read_text) | `utf-8` |
| _execute | langchain | `get_mcp_guide.py:21` | FILESYSTEM (pathlib.Path.read_text) | `utf-8` |
| _execute | langchain | `helpers.py:65` | MEMORY_READ (input_schema.get) | `properties` |
| _execute | langchain | `helpers.py:65` | MEMORY_READ (input_schema.get) | `properties` |
| _execute | langchain | `helpers.py:66` | MEMORY_READ (input_schema.get) | `required` |
| _execute | langchain | `helpers.py:66` | MEMORY_READ (input_schema.get) | `required` |
| _execute | langchain | `helpers.py:75` | MEMORY_READ (schema.get) | `title` |
| _execute | langchain | `helpers.py:75` | MEMORY_READ (schema.get) | `title` |
| _execute | langchain | `helpers.py:76` | MEMORY_READ (schema.get) | `type` |
| _execute | langchain | `helpers.py:76` | MEMORY_READ (schema.get) | `type` |
| _execute | langchain | `helpers.py:77` | MEMORY_READ (schema.get) | `description` |
| _execute | langchain | `helpers.py:77` | MEMORY_READ (schema.get) | `description` |
| _execute | langchain | `helpers.py:79` | MEMORY_READ (schema.get) | `default` |
| _execute | langchain | `helpers.py:79` | MEMORY_READ (schema.get) | `default` |
| _execute | langchain | `helpers.py:80` | MEMORY_READ (schema.get) | `advanced` |
| _execute | langchain | `helpers.py:80` | MEMORY_READ (schema.get) | `advanced` |
| _execute | langchain | `helpers.py:120` | MEMORY_READ (outputs.get) | `error` |
| _execute | langchain | `helpers.py:120` | MEMORY_READ (outputs.get) | `error` |
| _execute | langchain | `helpers.py:184` | MEMORY_READ (creds_manager.get) | `user_id` |
| _execute | langchain | `helpers.py:184` | MEMORY_READ (creds_manager.get) | `user_id` |
| _execute | langchain | `helpers.py:438` | MEMORY_READ (block.input_schema.get_credentials_fields().keys) | _(none)_ |
| _execute | langchain | `helpers.py:443` | MEMORY_READ (matched_credentials.keys) | _(none)_ |
| _execute | langchain | `helpers.py:473` | MEMORY_READ (input_schema.get) | `required` |
| _execute | langchain | `helpers.py:475` | MEMORY_READ (input_data.keys) | _(none)_ |
| _execute | langchain | `helpers.py:477` | MEMORY_READ (input_schema.get("properties").keys) | _(none)_ |
| _execute | langchain | `helpers.py:477` | MEMORY_READ (input_schema.get) | `properties` |
| _execute | langchain | `helpers.py:619` | MEMORY_READ (input_data.get) | `field_info.discriminator` |
| _execute | langchain | `helpers.py:619` | MEMORY_READ (input_data.get) | `field_info.discriminator` |
| _execute | langchain | `helpers.py:621` | MEMORY_READ (block.input_schema.model_fields.get) | `field_info.discriminator` |
| _execute | langchain | `helpers.py:621` | MEMORY_READ (block.input_schema.model_fields.get) | `field_info.discriminator` |
| _execute | langchain | `manage_folders.py:57` | MEMORY_READ (agents_map.get) | `tree.id` |
| _execute | langchain | `manage_folders.py:230` | MEMORY_READ (agents_map.get) | `f.id` |
| _execute | langchain | `run_agent.py:388` | MEMORY_READ (graph.input_schema.get) | `properties` |
| _execute | langchain | `run_agent.py:389` | MEMORY_READ (params.inputs.keys) | _(none)_ |
| _execute | langchain | `run_agent.py:390` | MEMORY_READ (input_properties.keys) | _(none)_ |
| _execute | langchain | `run_agent.py:437` | MEMORY_READ (graph.input_schema.get) | `required` |
| _execute | langchain | `run_agent.py:490` | MEMORY_READ (session.successful_agent_runs.get) | `graph.id` |
| _execute | langchain | `run_agent.py:512` | MEMORY_READ (session.successful_agent_runs.get) | `library_agent.graph_id` |
| _execute | langchain | `run_agent.py:655` | MEMORY_READ (session.successful_agent_schedules.get) | `graph.id` |
| _execute | langchain | `run_agent.py:690` | MEMORY_READ (session.successful_agent_schedules.get) | `library_agent.graph_id` |
| _execute | langchain | `run_mcp_tool.py:275` | MEMORY_READ (item.get) | `text` |
| _execute | langchain | `run_mcp_tool.py:277` | MEMORY_READ (item.get) | `type` |
| _execute | langchain | `sandbox.py:158` | FILESYSTEM (os.path.exists) | `path` |
| _execute | langchain | `search_docs.py:137` | MEMORY_READ (result.get) | `metadata` |
| _execute | langchain | `search_docs.py:138` | MEMORY_READ (metadata.get) | `path` |
| _execute | langchain | `search_docs.py:146` | MEMORY_READ (result.get) | `combined_score` |
| _execute | langchain | `search_docs.py:146` | MEMORY_READ (seen_docs[doc_path].get) | `combined_score` |
| _execute | langchain | `search_docs.py:154` | MEMORY_READ (x.get) | `combined_score` |
| _execute | langchain | `search_docs.py:171` | MEMORY_READ (result.get) | `metadata` |
| _execute | langchain | `search_docs.py:172` | MEMORY_READ (metadata.get) | `path` |
| _execute | langchain | `search_docs.py:173` | MEMORY_READ (metadata.get) | `doc_title` |
| _execute | langchain | `search_docs.py:174` | MEMORY_READ (metadata.get) | `section_title` |
| _execute | langchain | `search_docs.py:175` | MEMORY_READ (result.get) | `searchable_text` |
| _execute | langchain | `search_docs.py:176` | MEMORY_READ (result.get) | `combined_score` |
| _execute | langchain | `utils.py:104` | MEMORY_READ (cred_schema.get) | `title` |
| _execute | langchain | `utils.py:153` | MEMORY_READ (matched_credentials.keys) | _(none)_ |
| _execute | langchain | `utils.py:216` | MEMORY_READ (cred_schema["properties"]["provider"].get) | `const` |
| _execute | langchain | `utils.py:225` | MEMORY_READ (cred_schema["properties"]["type"].get) | `const` |
| _execute | langchain | `utils.py:493` | MEMORY_READ (credential.metadata.get) | `mcp_server_url` |
| _execute | langchain | `validate_agent.py:63` | MEMORY_READ (agent_json.get) | `nodes` |
| _execute | langchain | `web_fetch.py:106` | NETWORK (client.get) | `url` |
| _execute | langchain | `web_fetch.py:122` | MEMORY_READ (response.headers.get) | `content-type` |
| _execute | langchain | `workspace_files.py:120` | FILESYSTEM (sandbox.files.read) | `remote` |
| _execute | langchain | `workspace_files.py:135` | FILESYSTEM (builtins.open) | `validated` |
| _execute | langchain | `workspace_files.py:136` | FILESYSTEM (builtins.open.read) | _(none)_ |
| _execute | langchain | `workspace_files.py:327` | FILESYSTEM (builtins.open) | `expanded` |
| _execute | langchain | `workspace_files.py:328` | FILESYSTEM (builtins.open.read) | _(none)_ |
| _execute | langchain | `workspace_files.py:798` | MEMORY_READ (kwargs.get) | `k` |
| _execute | langchain | `simulator.py:88` | MEMORY_READ (schema.get) | `properties` |
| _execute | langchain | `simulator.py:88` | MEMORY_READ (schema.get) | `properties` |
| _execute | langchain | `simulator.py:89` | MEMORY_READ (schema.get) | `required` |
| _execute | langchain | `simulator.py:89` | MEMORY_READ (schema.get) | `required` |
| _execute | langchain | `simulator.py:92` | MEMORY_READ (pin_schema.get) | `type` |
| _execute | langchain | `simulator.py:92` | MEMORY_READ (pin_schema.get) | `type` |
| _execute | langchain | `simulator.py:189` | MEMORY_READ (output_schema.get("properties").keys) | _(none)_ |
| _execute | langchain | `simulator.py:189` | MEMORY_READ (output_schema.get) | `properties` |
| _execute | langchain | `simulator.py:189` | MEMORY_READ (output_schema.get("properties").keys) | _(none)_ |
| _execute | langchain | `simulator.py:189` | MEMORY_READ (output_schema.get) | `properties` |
| _execute | langchain | `simulator.py:359` | MEMORY_READ (result_schema.get) | `type` |
| _execute | langchain | `simulator.py:359` | MEMORY_READ (result_schema.get) | `type` |
| _execute | langchain | `simulator.py:360` | MEMORY_READ (result_schema.get) | `format` |
| _execute | langchain | `simulator.py:360` | MEMORY_READ (result_schema.get) | `format` |
| _execute | langchain | `simulator.py:401` | MEMORY_READ (input_data.get) | `value` |
| _execute | langchain | `simulator.py:401` | MEMORY_READ (input_data.get) | `value` |
| _execute | langchain | `simulator.py:407` | MEMORY_READ (input_data.get) | `options` |
| _execute | langchain | `simulator.py:407` | MEMORY_READ (input_data.get) | `options` |
| _execute | langchain | `simulator.py:414` | MEMORY_READ (block.output_schema.jsonschema().get("properties").get) | `result` |
| _execute | langchain | `simulator.py:414` | MEMORY_READ (block.output_schema.jsonschema().get) | `properties` |
| _execute | langchain | `simulator.py:414` | MEMORY_READ (block.output_schema.jsonschema().get("properties").get) | `result` |
| _execute | langchain | `simulator.py:414` | MEMORY_READ (block.output_schema.jsonschema().get) | `properties` |
| _execute | langchain | `simulator.py:419` | MEMORY_READ (input_data.get) | `name` |
| _execute | langchain | `simulator.py:419` | MEMORY_READ (input_data.get) | `name` |
| _execute | langchain | `simulator.py:428` | MEMORY_READ (input_data.get) | `format` |
| _execute | langchain | `simulator.py:428` | MEMORY_READ (input_data.get) | `format` |
| _execute | langchain | `simulator.py:429` | MEMORY_READ (input_data.get) | `value` |
| _execute | langchain | `simulator.py:429` | MEMORY_READ (input_data.get) | `value` |
| _execute | langchain | `simulator.py:430` | MEMORY_READ (input_data.get) | `name` |
| _execute | langchain | `simulator.py:430` | MEMORY_READ (input_data.get) | `name` |
| _execute | langchain | `simulator.py:435` | MEMORY_READ (input_data.get) | `escape_html` |
| _execute | langchain | `simulator.py:435` | MEMORY_READ (input_data.get) | `escape_html` |
| _execute | langchain | `simulator.py:448` | MEMORY_READ (output_schema.get) | `properties` |
| _execute | langchain | `simulator.py:448` | MEMORY_READ (output_schema.get) | `properties` |
| _execute | langchain | `simulator.py:475` | MEMORY_READ (output_schema.get) | `required` |
| _execute | langchain | `simulator.py:475` | MEMORY_READ (output_schema.get) | `required` |
| _execute | langchain | `simulator.py:477` | MEMORY_READ (output_properties.get) | `pin_name` |
| _execute | langchain | `simulator.py:477` | MEMORY_READ (output_properties.get) | `pin_name` |
| _execute | langchain | `simulator.py:493` | MEMORY_READ (pin_schema.get) | `type` |
| _execute | langchain | `simulator.py:493` | MEMORY_READ (pin_schema.get) | `type` |
| _execute | langchain | `utils.py:132` | MEMORY_READ (BLOCK_COSTS.get) | `block` |
| _execute | langchain | `utils.py:132` | MEMORY_READ (BLOCK_COSTS.get) | `block` |
| _execute | langchain | `utils.py:169` | MEMORY_READ (input_data.get) | `k` |
| _execute | langchain | `utils.py:169` | MEMORY_READ (input_data.get) | `k` |
| _execute | langchain | `utils.py:170` | MEMORY_READ (input_data.get) | `k` |
| _execute | langchain | `utils.py:170` | MEMORY_READ (input_data.get) | `k` |
| _execute | langchain | `file_content_parser.py:97` | MEMORY_READ (MIME_TO_FORMAT.get) | _(none)_ |
| _execute | langchain | `file_content_parser.py:105` | MEMORY_READ (_EXT_TO_FORMAT.get) | _(none)_ |
| _execute | langchain | `file_content_parser.py:136` | MEMORY_READ (_BINARY_PARSERS.get) | `fmt` |
| _execute | langchain | `file_content_parser.py:144` | MEMORY_READ (_TEXT_PARSERS.get) | `fmt` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `json.py:59` | MEMORY_READ (kwargs.get) | `indent` |
| _execute | langchain | `type.py:329` | MEMORY_READ (data.get) | `name` |
| _execute | langchain | `type.py:329` | MEMORY_READ (data.get) | `name` |

---

## Unclassified CEEs

**Total:** 189

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (0):**
None.

**LOW_RISK_UNTRACED tools (189):**
All 189 unclassified CEEs fall into the low-risk category. The majority are langchain `_execute` tool registration entry points across the backend copilot tool modules (e.g., `add_understanding.py:59`, `agent_browser.py:449`, `agent_browser.py:615`, `agent_browser.py:784`, `agent_output.py:408`, `ask_question.py:64`, `bash_exec.py:78`, `connect_integration.py:114`, `continue_run_block.py:52`, `create_agent.py:61`, `customize_agent.py:60`, `edit_agent.py:61`, `feature_requests.py:156`, `feature_requests.py:288`, `find_agent.py:36`, `find_block.py:85`, `find_library_agent.py:53`, `fix_agent.py:50`, `get_agent_building_guide.py:62`, `get_doc_page.py:67`, `get_mcp_guide.py:55`, `manage_folders.py:122`, `manage_folders.py:202`, `manage_folders.py:302`, `manage_folders.py:378`, `manage_folders.py:448`, `manage_folders.py:520`, `run_agent.py:171`, `run_block.py:64`, `run_mcp_tool.py:90`, `search_docs.py:84`, `validate_agent.py:47`, `web_fetch.py:86`, `workspace_files.py:449`, `workspace_files.py:567`, `workspace_files.py:772`, `workspace_files.py:941`). A large block of unclassified entries are also frontend React/TypeScript components and hooks from the AutoGPT Platform UI layer (e.g., `AdminAgentsDataTable.tsx`, `RunAgentTool`, `RunBlockTool`, `RunMCPToolComponent`, `ViewAgentOutputTool`, and numerous event handlers), as well as minified Google Analytics gtag.js function registrations (`b`, `ny`, `iz`) and `forge_agent.py:211 execute`. Additionally, several `__init__.py:28`, `__init__.py:38`, `_utils.py:44`, and `registry.py:146` entries carry policy gates and were therefore excluded from AFB04 classification.

---

## Coverage Gap Analysis

**Unresolved call edges:** 7432
**Unique entrypoints traced to sensitive ops:** 123

With 7432 unresolved call edges against a 1735-file codebase, there are approximately 4.3 unresolved edges per file -- an unusually high ratio indicating that AutoGPT's platform backend relies heavily on dynamic dispatch, plugin-style block registration, and runtime-resolved imports that the static call graph cannot fully traverse. The 123 unique entrypoints that do reach sensitive operations represent a lower-bound on actual exposure; the true number of reachable sensitive paths is likely substantially higher, as any of the 7432 unresolved edges could connect additional tool entry points to the same subprocess, filesystem, and network sinks already confirmed by the classified findings.

---

## Key Findings Summary

1. **Direct command injection surface confirmed.** The `bash_exec.py` -> `sandbox.py` path (CRITICAL, `sandbox.py:243`) traces tool-controlled input directly into `asyncio.create_subprocess_exec` with only one intermediate call and no authorization gate, making it a single-hop command injection primitive accessible to any LLM instruction.

2. **Zero authorization coverage across all 367 classified findings.** Every classified CEE -- critical, warning, and info -- carries "No policy gate detected," meaning the langchain `_execute` tool operates in a fully ungoverned state: subprocess execution, file writes, file reads, network fetches, and identity lookups are all equally accessible without any access control layer.

3. **Agent graph manipulation is fully LLM-controlled.** The `create_agent.py`, `customize_agent.py`, and `edit_agent.py` tools -- together accounting for a significant share of the warning and info findings -- allow the LLM to read and mutate agent graph state (nodes, links, metadata, IDs) without authorization checks, enabling an adversary to craft malicious agent topologies through prompt manipulation alone.

4. **Filesystem write paths carry tool-controlled and instruction-influenced input.** The `workspace_files.py` cluster (WARNING, lines 163-181) traces tool-controlled input into both `sandbox.files.write` and local `open(validated, "wb")` with `os.makedirs`, meaning LLM-supplied paths and content reach disk with no policy gate -- a direct arbitrary file write capability.

5. **GitHub identity data is reachable without authorization.** The `integration_creds.py` findings (INFO, lines 218-260) show that GitHub user identity fields -- name, email, login, and numeric ID -- are accessible through `aiohttp.ClientSession.get` to `https://api.github.com/user`, reachable from the `bash_exec.py:78` entry point without a policy gate, exposing user identity data to any LLM-directed tool call.

6. **The 7432-edge coverage gap substantially underestimates actual exposure.** The 189 unclassified CEEs include 37+ backend tool registration entry points whose full call graphs were not resolved; given that the 37 resolved entry points already produce 367 classified findings, the unresolved entries likely represent comparable additional exposure that falls outside the confirmed finding count.
