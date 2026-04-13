# Wyscan Security Report: Agno

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/agno-agi/agno
> **Framework(s) detected:** agno, pydantic-ai

## About This System

Agno (formerly Phidata) is a Python framework for building multi-modal, multi-agent systems with memory, knowledge, and tool use. It supports structured agent teams, web search, database access, and reasoning loops. Selected for evaluation because it is a framework-level system -- vulnerabilities here propagate to every application built on top of it -- and its broad tool integrations (web, databases, file systems, external APIs) make it a high-value target for assessing how framework-layer tool calls expose sensitive operations.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 2719 |
| Scan duration | 136.8s |
| Total CEEs detected | 239 |
| Classified findings | 152 |
| Unclassified CEEs | 87 |
| Unique entrypoints reaching sensitive ops | N/A |
| Unresolved call edges (coverage gap) | N/A |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| WARNING | 90 |
| INFO | 60 |
| UNCLASSIFIED | 87 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

Every classified CEE in this scan reports no policy gate in the analyzed call path. This is consistent with Agno's framework design, which delegates authorization entirely to application code -- meaning every cookbook example and downstream application inherits an ungoverned baseline. The two CRITICAL findings involve direct shell command execution with tool-controlled input, the most severe authorization gap class in the AFB04 taxonomy.

---

## Critical Findings

### [execute_shell_command] -> [subprocess.check_output]

| Field | Value |
|-------|-------|
| File | `external_tool_execution.py:29` |
| Entry point | `external_tool_execution.py:18` |
| Framework | agno |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `command` |

**Code:**
```
return subprocess.check_output(command, shell=True).decod...
```

**Risk:** A tool-controlled `command` string is passed directly to `subprocess.check_output` with `shell=True`, enabling arbitrary shell injection. Any instruction that reaches this tool can execute arbitrary OS commands in the agent's process context with no authorization check in the call path.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [run_shell_command] -> [subprocess.check_output]

| Field | Value |
|-------|-------|
| File | `external_tool_execution_stream.py:38` |
| Entry point | `external_tool_execution_stream.py:31` |
| Framework | agno |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `command` |

**Code:**
```
return subprocess.check_output(shlex.split(command)).deco...
```

**Risk:** Tool-controlled input flows into `subprocess.check_output` via `shlex.split`. While `shlex.split` prevents shell metacharacter injection compared to `shell=True`, the tool still executes arbitrary commands selected by the agent with no policy gate. This is the team-variant of the same PROCESS_EXECUTION pattern detected in the single-agent cookbook.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

## Warning Findings

### MEMORY_WRITE (2 findings)

Knowledge base insertion operations reached from tool calls with no authorization gate. Both findings involve `.insert()` calls into persistent knowledge stores, with tool-controlled or instruction-influenced input flowing into the write arguments. A compromised or hijacked agent instruction could poison the knowledge base with adversary-controlled content.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|-----------------------|
| save_learning | agno | `human_in_the_loop.py:94` | `title` | No |
| save_validated_query | agno | `save_query.py:73` | `payload` | Yes |

---

### STATE_MUTATION (12 findings)

Multiple tools append to in-memory lists and session state without authorization gates. The dominant pattern is `lines.append(...)` building formatted output strings from tool-controlled or instruction-influenced data, plus direct `session_state` and `watchlist` mutations. While individual appends are low-impact, the pattern demonstrates that Agno tools routinely mutate shared state without policy checks.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|-----------------------|
| list_sources | agno | `awareness.py:46` | `f"### {source['source_name']} (\`{source['source_type']}\`)"` | No |
| list_sources | agno | `awareness.py:48` | `description` | No |
| list_sources | agno | `awareness.py:49` | `""` | No |
| list_sources | agno | `awareness.py:53` | `**Capabilities:**` | No |
| list_sources | agno | `awareness.py:55` | `f"  - {cap}"` | No |
| list_sources | agno | `awareness.py:56` | `""` | No |
| list_sources | agno | `awareness.py:59` | `**Where to find things:**` | No |
| list_sources | agno | `awareness.py:61` | `f"  - {key}: \`{value}\`"` | No |
| list_sources | agno | `awareness.py:62` | `""` | No |
| list_sources | agno | `awareness.py:66` | `**Buckets:**` | No |
| list_sources | agno | `awareness.py:68` | `f"  - **{bucket['name']}**: {bucket.get('description', '')}"` | No |
| list_sources | agno | `awareness.py:71` | `""` | No |
| list_sources | agno | `awareness.py:73` | `""` | No |
| get_metadata | agno | `awareness.py:129` | `f"{icon} **{name}/**"` | No |
| get_metadata | agno | `awareness.py:134` | `f"{icon} {name}{size_info}"` | No |
| get_metadata | agno | `awareness.py:137` | `f"   \`{item['id']}\`"` | No |
| get_metadata | agno | `awareness.py:152` | `f"**{key}:** {value}"` | No |
| get_metadata | agno | `awareness.py:169` | `f"{icon} **{name}/**"` | No |
| get_metadata | agno | `awareness.py:177` | `f"{icon} {name}{size_info}"` | No |
| list_buckets | agno | `s3.py:41` | `f"**{bucket['name']}**"` | No |
| list_buckets | agno | `s3.py:43` | `f"  {bucket['description']}"` | No |
| list_buckets | agno | `s3.py:45` | `f"  Region: {bucket['region']}"` | No |
| list_buckets | agno | `s3.py:46` | `""` | No |
| list_files | agno | `s3.py:72` | `f"[bucket] **{item['name']}/**"` | No |
| list_files | agno | `s3.py:74` | `f"[dir] **{item['name']}/**"` | No |
| list_files | agno | `s3.py:79` | `f"[file] {item['name']} ({size_str}, {modified})"` | No |
| list_files | agno | `s3.py:80` | `f"   \`{item['id']}\`"` | No |
| search_files | agno | `s3.py:110` | `f"**{result['key']}**"` | No |
| search_files | agno | `s3.py:111` | `f"  Bucket: {result['bucket']}"` | No |
| search_files | agno | `s3.py:112` | `f"  Match: {result['match_type']}"` | No |
| search_files | agno | `s3.py:115` | ` ``` ` | No |
| search_files | agno | `s3.py:117` | `f"  {snippet_line}"` | No |
| search_files | agno | `s3.py:118` | ` ``` ` | No |
| search_files | agno | `s3.py:120` | `f"  Path: \`{result['id']}\`"` | No |
| search_files | agno | `s3.py:121` | `""` | No |
| read_file | agno | `s3.py:158` | `---` | No |
| read_file | agno | `s3.py:160` | `f"Modified: {meta['modified']}"` | No |
| read_file | agno | `s3.py:162` | `f"Size: {_format_size(meta['size'])}"` | No |
| read_file | agno | `s3.py:163` | `---` | No |
| read_file | agno | `s3.py:164` | `""` | No |
| read_file | agno | `s3.py:166` | `content` | No |
| add_to_watchlist | agno | `confirmation_with_session_state.py:37` | `symbol` | Yes |
| add_item | agno | `retry_tool_call_from_post_hook.py:49` | `item` | Yes |
| get_session_runs | pydantic-ai | `mcp.py:359` | N/A | No |
| get_session_runs | pydantic-ai | `mcp.py:362` | N/A | No |
| get_session_runs | pydantic-ai | `mcp.py:364` | N/A | No |
| get_session_runs | pydantic-ai | `mcp.py:367` | N/A | No |
| get_session_runs | pydantic-ai | `mcp.py:369` | N/A | No |
| get_session_runs | pydantic-ai | `mcp.py:371` | N/A | No |

---

### FILESYSTEM (1 finding)

A direct connector write operation is reachable from the `write_file` tool with both tool-controlled input and instruction-influenced context in the call path. No authorization gate is present, meaning an agent can write arbitrary content to any accessible path.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|-----------------------|
| write_file | agno | `s3.py:192` | `parent` | Yes |

---

### NETWORK (29 findings)

Numerous tools reach external HTTP endpoints via `httpx.get` and `httpx.AsyncClient.get` without any authorization gate. The dominant pattern is the `get_top_hackernews_stories` tool, which appears across multiple cookbook examples and fires external requests to HackerNews and other APIs. The `get_current_weather` tool similarly contacts geocoding and forecast APIs. None have a policy gate in the analyzed path.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|-----------------------|
| get_top_hackernews_stories | agno | `confirmation_advanced.py:34` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `confirmation_advanced.py:40` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `confirmation_advanced.py:46` | `story` | No |
| get_top_hackernews_stories | agno | `confirmation_required.py:34` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `confirmation_required.py:40` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `confirmation_required.py:46` | `story` | No |
| get_top_hackernews_stories | agno | `approval_async.py:34` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `approval_async.py:38` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `approval_async.py:42` | `story` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:33` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:37` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:41` | `story` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:32` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:36` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `approval_basic.py:40` | `story` | No |
| get_top_hackernews_stories | agno | `human_in_the_loop.py:63` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `human_in_the_loop.py:68` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `async_tool_decorator.py:27` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `async_tool_decorator.py:34` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `cache_tool_calls.py:22` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `cache_tool_calls.py:28` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `cache_tool_calls.py:34` | `story` | No |
| get_top_hackernews_stories | agno | `tool_decorator_with_hook.py:36` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `tool_decorator_with_hook.py:41` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `tool_decorator_with_instructions.py:34` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `tool_decorator_with_instructions.py:40` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `tool_decorator_with_instructions.py:44` | `f"{story.get('title')} - {story.get('url', 'No URL')}"` | No |
| get_top_hackernews_stories | agno | `tool_decorator.py:25` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `tool_decorator.py:30` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories | agno | `tool_decorator.py:73` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `tool_decorator.py:81` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_current_weather | agno | `tool_decorator.py:102` | `https://geocoding-api.open-meteo.com/v1/search` | No |
| get_current_weather | agno | `tool_decorator.py:118` | `https://api.open-meteo.com/v1/forecast` | No |
| get_top_hackernews_stories | agno | `pre_and_post_hooks.py:38` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories | agno | `pre_and_post_hooks.py:43` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| get_top_hackernews_stories_async | agno | `pre_and_post_hooks.py:80` | `https://hacker-news.firebaseio.com/v0/topstories.json` | No |
| get_top_hackernews_stories_async | agno | `pre_and_post_hooks.py:87` | `f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"` | No |
| save_intent_discovery | agno | `save_discovery.py:61` | `payload` | Yes |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| list_sources | agno | `awareness.py:33` | MEMORY_READ | `sources` |
| list_sources | agno | `awareness.py:47` | MEMORY_READ | `description` |
| list_sources | agno | `awareness.py:52` | MEMORY_READ | `capabilities` |
| list_sources | agno | `awareness.py:58` | MEMORY_READ | `common_locations` |
| list_sources | agno | `awareness.py:65` | MEMORY_READ | `buckets` |
| list_sources | agno | `awareness.py:69` | MEMORY_READ | `description` |
| get_metadata | agno | `awareness.py:103` | MEMORY_READ | N/A |
| get_metadata | agno | `awareness.py:119` | MEMORY_READ | `type` |
| get_metadata | agno | `awareness.py:120` | MEMORY_READ | `name` |
| get_metadata | agno | `awareness.py:122` | MEMORY_READ | `type` |
| get_metadata | agno | `awareness.py:132` | MEMORY_READ | `size` |
| get_metadata | agno | `awareness.py:136` | MEMORY_READ | `id` |
| get_metadata | agno | `awareness.py:146` | FILESYSTEM | `path` |
| get_metadata | agno | `awareness.py:149` | MEMORY_READ | `metadata` |
| get_metadata | agno | `awareness.py:159` | MEMORY_READ | `type` |
| get_metadata | agno | `awareness.py:160` | MEMORY_READ | `name` |
| get_metadata | agno | `awareness.py:162` | MEMORY_READ | `type` |
| get_metadata | agno | `awareness.py:172` | MEMORY_READ | `size` |
| get_metadata | agno | `awareness.py:174` | MEMORY_READ | `modified` |
| get_metadata | agno | `awareness.py:196` | MEMORY_READ | `item_type` |
| list_buckets | agno | `s3.py:42` | MEMORY_READ | `description` |
| list_buckets | agno | `s3.py:44` | MEMORY_READ | `region` |
| list_files | agno | `s3.py:76` | MEMORY_READ | `size` |
| list_files | agno | `s3.py:78` | MEMORY_READ | `modified` |
| search_files | agno | `s3.py:114` | MEMORY_READ | `snippet` |
| read_file | agno | `s3.py:149` | FILESYSTEM | `path` |
| read_file | agno | `s3.py:156` | MEMORY_READ | `metadata` |
| read_file | agno | `s3.py:159` | MEMORY_READ | `modified` |
| read_file | agno | `s3.py:161` | MEMORY_READ | `size` |
| read_file | agno | `s3.py:166` | MEMORY_READ | `content` |
| add_to_watchlist | agno | `confirmation_with_session_state.py:34` | MEMORY_READ | `watchlist` |
| lookup_product_price | agno | `tool_call_limit.py:22` | MEMORY_READ | `This product is not in the catalog.` |
| lookup_shipping_time | agno | `tool_call_limit.py:33` | MEMORY_READ | `Unknown shipping zone.` |
| get_city_timezone | agno | `tool_choice.py:23` | MEMORY_READ | `Unsupported city for this example.` |
| greet | pydantic-ai | `server.py:24` | IDENTITY | `x-user-id` |
| greet | pydantic-ai | `server.py:25` | IDENTITY | `x-session-id` |
| greet | pydantic-ai | `server.py:26` | IDENTITY | `x-agent-name` |
| greet | pydantic-ai | `server.py:27` | IDENTITY | `x-team-name` |
| get_weather | agno | `tool_use.py:28` | MEMORY_READ | `city` |
| greet | pydantic-ai | `server.py:27` | IDENTITY | `x-user-id` |
| greet | pydantic-ai | `server.py:28` | IDENTITY | `x-tenant-id` |
| greet | pydantic-ai | `server.py:29` | IDENTITY | `x-agent-name` |
| get_top_hackernews_stories | agno | `async_tool_decorator.py:23` | MEMORY_READ | `num_stories` |
| get_top_hackernews_stories | agno | `tool_decorator_with_hook.py:33` | MEMORY_READ | `num_stories` |
| get_top_hackernews_stories | agno | `tool_decorator_with_instructions.py:44` | MEMORY_READ | `title` |
| get_top_hackernews_stories | agno | `tool_decorator.py:22` | MEMORY_READ | `num_stories` |
| get_top_hackernews_stories | agno | `tool_decorator.py:69` | MEMORY_READ | `num_stories` |
| get_current_weather | agno | `tool_decorator.py:95` | MEMORY_READ | `city` |
| get_current_weather | agno | `tool_decorator.py:112` | MEMORY_READ | `results` |
| get_current_weather | agno | `tool_decorator.py:128` | MEMORY_READ | `current_weather` |
| get_top_hackernews_stories | agno | `pre_and_post_hooks.py:35` | MEMORY_READ | `num_stories` |
| get_top_hackernews_stories_async | agno | `pre_and_post_hooks.py:76` | MEMORY_READ | `num_stories` |
| get_session_runs | pydantic-ai | `mcp.py:352` | MEMORY_READ | `runs` |
| get_session_runs | pydantic-ai | `mcp.py:361` | MEMORY_READ | `agent_id` |
| get_session_runs | pydantic-ai | `mcp.py:366` | MEMORY_READ | `workflow_id` |
| get_session_runs | pydantic-ai | `mcp.py:368` | MEMORY_READ | `team_id` |
| get_session_run | pydantic-ai | `mcp.py:413` | MEMORY_READ | `runs` |
| get_session_run | pydantic-ai | `mcp.py:419` | MEMORY_READ | `run_id` |
| get_session_run | pydantic-ai | `mcp.py:426` | MEMORY_READ | `workflow_id` |
| get_session_run | pydantic-ai | `mcp.py:428` | MEMORY_READ | `team_id` |

---

## Unclassified CEEs

**Total:** 87

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (26):**
- `send_email` (user_input_required.py:19, external_tool_execution.py:25)
- `deploy_to_production` (approval_external_execution.py:20, approval_team.py:21, confirmation_required_async_stream.py:28, confirmation_required_async.py:17, confirmation_required_stream.py:30)
- `delete_user_data` (approval_list_and_resolve.py:20, audit_approval_async.py:20, audit_approval_confirmation.py:20)
- `send_bulk_email` (approval_list_and_resolve.py:31)
- `run_security_scan` (audit_approval_external.py:19)
- `critical_action` (audit_approval_overview.py:20)
- `approve_deployment` (team_tool_confirmation_stream.py:30, team_tool_confirmation.py:18)
- `send_money` (approval_user_input.py:20 x2)
- `delete_user_account` (confirmation_rejected_stream.py:28, confirmation_rejected.py:17)
- `book_flight` (user_input_required_stream.py:28)
- `process_payment` (pydantic_tool_input.py:113)
- `create_user` (pydantic_tool_input.py:76, complex_input_types.py:61)
- `submit_order` (pydantic_tool_input.py:144)
- `plan_delivery` (pydantic_tool_input.py:185)
- `transfer_funds` (audit_approval_user_input.py:19)

**MEDIUM_RISK_UNTRACED tools (11):**
- `write_file` (s3.py:170)
- `read_file` (s3.py:125)
- `search_files` (s3.py:84)
- `create_session` (mcp.py:218)
- `rename_session` (mcp.py:433)
- `delete_session` (mcp.py:558)
- `delete_sessions` (mcp.py:583)
- `create_memory` (mcp.py:613)
- `update_memory` (mcp.py:759)
- `delete_memory` (mcp.py:806)
- `delete_memories` (mcp.py:827)

**LOW_RISK_UNTRACED tools (50):**
Remaining 50 unclassified CEEs are UI helpers, test utilities, pure computation tools (e.g., `calculate_compound_interest`, `multiply_number`, `generate_haiku`), read-only lookup tools (`get_weather`, `get_events`, `lookup_product_price`), framework internals (`config`, `run_agent`, `run_team`, `get_sessions`, `get_session`, `get_memory`, `get_memories`, `update_session`), and interoperability stubs (`autogen_instantiation`, `crewai_instantiation`, `langgraph_instantiation`).

---

## Coverage Gap Analysis

**Unresolved call edges:** N/A (not reported in scan output)
**Unique entrypoints traced to sensitive ops:** N/A (not reported in scan output)

The agno scan processed 2719 files in 136.8s but did not emit a coverage gap or unique entrypoint count in the footer -- these metrics may require a deeper call graph resolution pass. Given the 87 unclassified CEEs and the breadth of the cookbook, actual sensitive operation reachability is likely higher than the 152 classified findings indicate. The presence of HIGH_RISK_UNTRACED tools such as `transfer_funds`, `deploy_to_production`, and `delete_user_data` suggests significant ungoverned surface area that static tracing did not resolve.

---

## Key Findings Summary

1. Both CRITICAL findings involve direct shell command execution (`subprocess.check_output`) with tool-controlled input and no policy gate -- the highest-severity AFB04 pattern, enabling arbitrary OS command injection from agent instructions.
2. 100% of 152 classified findings report no policy gate detected, confirming Agno's framework design defers all authorization to application-layer code, which cookbook examples universally omit.
3. 26 HIGH_RISK_UNTRACED tools -- including `transfer_funds`, `send_money`, `deploy_to_production`, `delete_user_data`, and `send_bulk_email` -- appear in the unclassified set, meaning their execution paths were not resolved by static analysis and their authorization status is unknown.
4. The dominant warning pattern (90 findings) is unguarded state mutation and in-memory list appends across S3, awareness, and session tools, demonstrating framework-wide absence of write authorization controls.
5. Network operations (httpx.get, httpx.AsyncClient.get) are reachable from at least 12 distinct tool registrations across multiple cookbook contexts, none with request-level authorization gates.
6. The 11 MEDIUM_RISK_UNTRACED session and memory management tools (`create_memory`, `delete_session`, `rename_session`, etc.) in the AgnoOS MCP server represent a persistent state attack surface that static tracing could not fully resolve.
