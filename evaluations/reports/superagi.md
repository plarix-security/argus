# Wyscan Security Report: SuperAGI

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/TransformerOptimus/SuperAGI
> **Framework(s) detected:** langchain, registration

## About This System

SuperAGI is an open-source autonomous AGI framework providing a self-hosted infrastructure for deploying, managing, and running AI agents. It features an agent marketplace, tool integrations (web browsing, code execution, email, calendars), performance telemetry, and a GUI console. Selected for evaluation because it combines broad tool access with a marketplace model that allows third-party tool installation, expanding the attack surface beyond the core codebase and making supply-chain authorization analysis especially relevant.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 362 |
| Scan duration | 5.4s |
| Total CEEs detected | 125 |
| Classified findings | 85 |
| Unclassified CEEs | 40 |
| Unique entrypoints reaching sensitive ops | 9 |
| Unresolved call edges (coverage gap) | 966 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| WARNING | 48 |
| INFO | 35 |
| UNCLASSIFIED | 40 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

Every traced path from a LangChain tool entry point to a sensitive operation -- file deletion, filesystem writes, email dispatch, network requests, and calendar mutations -- proceeds without any detected authorization check or policy gate. The marketplace model amplifies this risk: third-party tools installed from the marketplace inherit the same ungoverned execution environment as built-in tools, meaning supply-chain compromise or a malicious marketplace tool immediately gains the full sensitive-operation surface. The two CRITICAL findings involve `os.remove` invoked with tool-controlled input, establishing that agent-controlled data can directly determine which files are deleted without any intervening authorization step.

---

## Critical Findings

### [_execute (delete_file)] -> [os.remove]

| Field | Value |
|-------|-------|
| File | `delete_file.py:61:17` |
| Entry point | `delete_file.py:36` |
| Framework | langchain |
| Operation type | FILESYSTEM |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `final_path` |

**Code:**
```
os.remove(final_path)
```

**Risk:** The `_execute` handler in `delete_file.py` passes tool-controlled input directly as the path argument to `os.remove`, meaning the agent's instruction context determines which file is deleted with no policy gate intercepting the call. In a self-hosted deployment with broad filesystem access, this allows an agent operating under an adversarial instruction to delete arbitrary files within the accessible path space. The resource hint `final_path` confirms the deletion target is derived from tool input rather than a hardcoded safe value.

**AFB04 classification:** Unauthorized Action -- FILESYSTEM

---

### [_execute (read_file)] -> [os.remove]

| Field | Value |
|-------|-------|
| File | `read_file.py:99:13` |
| Entry point | `read_file.py:43` |
| Framework | langchain |
| Operation type | FILESYSTEM |
| Tool-controlled input | Yes |
| Instruction-influenced | No |
| Resource hint | `temporary_file_path` |

**Code:**
```
os.remove(temporary_file_path)
```

**Risk:** The read file tool invokes `os.remove` on a temporary file path derived from tool-controlled input as part of its cleanup logic. While this is likely intended as a temp-file cleanup, the absence of any path sanitization or sandboxing means the `temporary_file_path` value can be influenced through tool arguments to target files outside the intended temp directory. The fact that a read-oriented tool can trigger file deletion without a policy gate represents an unexpected secondary destructive capability.

**AFB04 classification:** Unauthorized Action -- FILESYSTEM

---

## Warning Findings

### NETWORK (8 findings)

Network operations are reachable from multiple `_execute` handlers for Apollo search, DALL-E image generation, Stable Diffusion, Instagram posting, and Searx search scraping. Several of these have tool-controlled input traced into the request arguments -- notably `apollo_search.py` passes tool-controlled input to `requests.post` URL construction, `stable_diffusion_image_gen.py` passes instruction-influenced input to a `requests.post` call with a constructed Stability AI endpoint URL, and `dalle_image_gen.py` passes instruction-influenced input to `requests.get`. Instagram posting reaches three separate `requests.post` calls for account ID retrieval, media container creation, and media publishing -- all ungoverned.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute (apollo_search) | langchain | apollo_search.py:127:20 | url | Yes |
| _execute (dalle_image_gen) | langchain | dalle_image_gen.py:69:20 | url | Yes |
| _execute (stable_diffusion) | langchain | stable_diffusion_image_gen.py:83:20 | f"https://api.stability.ai/..." | Yes |
| _execute (instagram) | langchain | instagram.py:177:18 | url_to_get_acc_id | No |
| _execute (instagram) | langchain | instagram.py:185:20 | url_to_create_media_container | No |
| _execute (instagram) | langchain | instagram.py:193:20 | url_to_post_media_container | No |
| _execute (marketplace/handleAddTool) | registration | DashboardService.js:56:9 | http | No |
| _execute (marketplace/installFromMarketplace) | registration | DashboardService.js:132:9 | http | No |
| _execute (marketplace/handleInstallClick) | registration | DashboardService.js:176:9 | http | No |
| _execute (searx) | langchain | search_scraper.py:41:11 | /search | Yes |

---

### FILESYSTEM (10 findings)

Filesystem write, read, directory creation, and directory traversal operations are reachable from file tool `_execute` handlers without policy gates. The `append_file.py` tool passes tool-controlled and instruction-influenced input to both `os.makedirs` and `open(..., 'a+')` then `file.write(content)`, meaning agent instructions directly control both the file path and the written content. `read_file.py` similarly passes tool-controlled input to `builtins.open` and `os.makedirs`. `list_files.py` passes instruction-influenced input to `os.walk`, enabling directory traversal enumeration. Cross-file paths through `resource_helper.py` indicate shared filesystem utilities used across multiple tools inherit the same ungoverned access.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute (append_file) | langchain | append_file.py:69:13 | directory | Yes |
| _execute (append_file) | langchain | append_file.py:70:18 | final_path | Yes |
| _execute (append_file) | langchain | append_file.py:71:17 | content | Yes |
| _execute (read_file) | langchain | read_file.py:68:22 | temporary_file_path | Yes |
| _execute (read_file) | langchain | read_file.py:70:21 | contents | Yes |
| _execute (read_file) | langchain | read_file.py:75:9 | directory | Yes |
| _execute (read_file) | langchain | read_file.py:89:17 | -- | No |
| _execute (delete_file via resource_helper) | langchain | resource_helper.py:142:13 | directory | No |
| _execute (append_file via resource_helper) | langchain | resource_helper.py:142:13 | directory | Yes |
| _execute (list_files) | langchain | list_files.py:68:17 | file | Yes |

---

### STATE_MUTATION -- data structure appends (14 findings)

A large number of `_execute` handlers append external or instruction-influenced data to in-memory collections without policy gates. This pattern appears across Apollo search (`people_list.append`), DuckDuckGo search (`links.append`, `results.append`, `webpages.append`), email reading (`messages.append`), email sending (`conn.append`), file operations (`data.append`, `content.append`, `file_names.append`, `found_files.append`), GitHub PR review (`pull_request_arr_parts.append`), Google Calendar (`attendees_list.append`, `csv_data.append`), Google Search (`results.append`), Stable Diffusion (`base64_strings.append`), and Searx (`sources.append`, `result_list.append`). Instruction-influenced data is flagged as present in several of these paths, meaning adversarially crafted web content or email content can influence what gets appended to agent-visible collections.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute (apollo_search) | langchain | apollo_search.py:78:17 | first_name | No |
| _execute (write_code) | langchain | write_code.py:106:13 | file_name | No |
| _execute (duck_duck_go) | langchain | duck_duck_go_search.py:66:13 | href | No |
| _execute (duck_duck_go) | langchain | duck_duck_go_search.py:96:13 | title | Yes |
| _execute (duck_duck_go) | langchain | duck_duck_go_search.py:126:17 | content | No |
| _execute (read_email) | langchain | read_email.py:61:13 | email_msg | No |
| _execute (send_email_attachment) | langchain | send_email_attachment.py:123:13 | draft_folder | No |
| _execute (send_email) | langchain | send_email.py:67:13 | draft_folder | No |
| _execute (validate_csv via read_file) | langchain | validate_csv.py:17:21 | row | No |
| _execute (review_pull_request) | langchain | review_pull_request.py:118:17 | current_part | No |
| _execute (review_pull_request) | langchain | review_pull_request.py:123:9 | current_part | No |
| _execute (create_calendar_event) | langchain | create_calendar_event.py:38:13 | email_id | No |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:66:13 | event_id | No |
| _execute (google_search) | langchain | google_search.py:64:13 | snippets | No |
| _execute (stable_diffusion) | langchain | stable_diffusion_image_gen.py:62:13 | base64 | No |
| _execute (searx) | langchain | search_scraper.py:97:13 | -- | No |
| _execute (searx) | langchain | search_scraper.py:102:9 | result | No |

---

### COMMUNICATION (4 findings)

Email sending via `smtplib.SMTP` is reachable from both `send_email.py` and `send_email_attachment.py` `_execute` handlers without any policy gate. Both tools reach `smtplib.SMTP` (SMTP connection establishment) and `smtp.send_message` (actual transmission), and both `send_message` call sites are flagged with instruction-influenced input present in the path, meaning email message content is directly shaped by agent instruction context. There is no recipient validation, rate limiting gate, or human-in-the-loop confirmation detected.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute (send_email_attachment) | langchain | send_email_attachment.py:137:18 | smtp_host | No |
| _execute (send_email_attachment) | langchain | send_email_attachment.py:141:17 | message | No |
| _execute (send_email) | langchain | send_email.py:81:18 | smtp_host | No |
| _execute (send_email) | langchain | send_email.py:85:17 | message | No |

---

### INFRASTRUCTURE -- Google Calendar (6 findings)

Google Calendar operations -- event creation, deletion, retrieval, and listing -- are all reachable from their respective `_execute` handlers without any policy gate. `create_calendar_event.py` reaches both `service.events().insert` and `service.events().insert.execute`, with tool-controlled input traced into the insert arguments. `delete_calendar_event.py` reaches `service.events().delete` and its `execute` call. These operations modify a user's primary calendar directly from agent instruction without authorization confirmation.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _execute (create_calendar_event) | langchain | create_calendar_event.py:63:17 | primary | Yes |
| _execute (create_calendar_event) | langchain | create_calendar_event.py:63:17 | -- | No |
| _execute (delete_calendar_event) | langchain | delete_calendar_event.py:33:22 | primary | No |
| _execute (delete_calendar_event) | langchain | delete_calendar_event.py:33:22 | -- | No |
| _execute (event_details_calendar) | langchain | event_details_calendar.py:31:22 | -- | No |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:53:13 | -- | No |
| _execute (event_details_calendar) | langchain | event_details_calendar.py:43:21 | email | No |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| _execute (improve_code) | langchain | prompt_reader.py:9:17 | builtins.open | file_path |
| _execute (write_code) | langchain | prompt_reader.py:9:17 | builtins.open | file_path |
| _execute (review_pull_request) | langchain | prompt_reader.py:9:17 | builtins.open | file_path |
| _execute (thinking/tools) | langchain | prompt_reader.py:9:17 | builtins.open | file_path |
| _execute (improve_code) | langchain | prompt_reader.py:10:28 | builtins.open.read | -- |
| _execute (write_code) | langchain | prompt_reader.py:10:28 | builtins.open.read | -- |
| _execute (review_pull_request) | langchain | prompt_reader.py:10:28 | builtins.open.read | -- |
| _execute (thinking/tools) | langchain | prompt_reader.py:10:28 | builtins.open.read | -- |
| _execute (write_code) | langchain | token_counter.py:62:21 | dict.keys | -- |
| _execute (review_pull_request) | langchain | token_counter.py:62:21 | dict.keys | -- |
| _execute (read_file) | langchain | validate_csv.py:7:10 | builtins.open | file_path |
| _execute (read_file) | langchain | validate_csv.py:8:33 | builtins.open.read | -- |
| _execute (read_file) | langchain | validate_csv.py:13:14 | builtins.open | file_path |
| _execute (improve_code) | langchain | improve_code.py:83:28 | result.get | response |
| _execute (improve_code) | langchain | improve_code.py:88:27 | response.get | choices |
| _execute (read_email) | langchain | read_email.py:79:47 | part.get | Content-Disposition |
| _execute (send_email_attachment) | langchain | send_email_attachment.py:75:42 | os.path.exists | final_path |
| _execute (send_email_attachment) | langchain | send_email_attachment.py:77:18 | builtins.open | final_path |
| _execute (send_email_attachment) | langchain | send_email_attachment.py:78:35 | builtins.open.read | -- |
| _execute (list_files) | langchain | list_files.py:61:34 | os.walk | directory |
| _execute (read_file) | langchain | read_file.py:72:38 | os.path.exists | final_path |
| _execute (create_calendar_event) | langchain | create_calendar_event.py:64:121 | event.get | htmlLink |
| _execute (event_details_calendar) | langchain | event_details_calendar.py:31:22 | service.events().get | primary |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:73:20 | query_parameters.get | eid |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:74:19 | item.get | summary |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:75:22 | item['start'].get | dateTime |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:76:20 | item['end'].get | dateTime |
| _execute (list_calendar_events) | langchain | list_calendar_events.py:77:56 | item.get | attendees |
| _execute (instagram) | langchain | instagram.py:203:18 | builtins.open | file_path |
| _execute (instagram) | langchain | instagram.py:204:35 | builtins.open.read | -- |
| _execute (searx) | langchain | search_scraper.py:82:18 | result_div.find | h4 |
| _execute (searx) | langchain | search_scraper.py:85:16 | header.find | a |
| _execute (searx) | langchain | search_scraper.py:88:40 | result_div.find | p |
| _execute (searx) | langchain | search_scraper.py:91:29 | result_div.find | pull-right |
| _execute (searx) | langchain | search_scraper.py:93:14 | result_div.find | engines |

---

## Unclassified CEEs

**Total:** 40

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (4):**
- `send_email.py:31` -- `_execute` (email sending)
- `send_email_attachment.py:47` -- `_execute` (email with attachment)
- `send_message.py:38` -- `_execute` (messaging)
- `send_tweets.py:24` -- `_execute` (Twitter/X posting)

**MEDIUM_RISK_UNTRACED tools (8):**
- `write_file.py:39` -- `_execute`
- `delete_file.py:36` -- `_execute` (file tool)
- `delete_file.py:50` -- `_execute` (GitHub file tool)
- `read_file.py:43` -- `_execute`
- `append_file.py:38` -- `_execute`
- `list_files.py:33` -- `_execute`
- `add_file.py:52` -- `_execute` (GitHub)
- `search_repo.py:42` -- `_execute`

**LOW_RISK_UNTRACED tools (28):**
The remaining 28 unclassified CEEs include frontend UI event handlers (`clearLocalStorage`, `handleClickOutside` in AgentCreate, AgentSchedule, KnowledgeForm, KnowledgeTemplate, and ToolkitWorkspace), tool base class registration (`base_tool.py:171`), code tools (`improve_code.py`, `write_code.py`), search tools (`duck_duck_go.py`, `google_search.py`, `google_serp_search.py`, `searx.py`), GitHub tools (`fetch_pull_request.py`, `review_pull_request.py`), calendar tools (`create_calendar_event.py`, `delete_calendar_event.py`, `event_details_calendar.py`, `list_calendar_events.py`), image generation tools (`dalle_image_gen.py`, `stable_diffusion_image_gen.py`), social tools (`instagram.py`, `tools.py:36`, `tools.py:48`), and knowledge tools (`knowledge_search.py`, `query_resource.py`, `apollo_search.py`). Note: several of these (email, calendar, social tools) have classified WARNING findings traced from their entry points, meaning the unclassified registration is a duplicate of already-analyzed paths.

---

## Coverage Gap Analysis

**Unresolved call edges:** 966
**Unique entrypoints traced to sensitive ops:** 9

The coverage gap of 966 unresolved edges across 362 files is moderate and consistent with a mixed Python/JavaScript codebase where cross-language calls and dynamic dispatch are common. Only 9 unique entrypoints were traced to sensitive operations -- a notably low number given the breadth of tools in the marketplace -- suggesting that many tool execution paths were not fully resolved by the call graph, and the true number of entrypoints reaching sensitive operations is higher. The marketplace installation mechanism (`handleAddTool`, `installFromMarketplace`, `handleInstallClick`) is represented in WARNING findings through API post calls, confirming that the tool installation surface is partially analyzed but the downstream execution paths of installed marketplace tools fall into the coverage gap.

---

## Key Findings Summary

1. Both CRITICAL findings involve `os.remove` called with tool-controlled input -- one from the dedicated file deletion tool and one as a side effect of the file read tool's temp cleanup -- establishing that agent-controlled arguments can determine file deletion targets without any authorization gate.
2. All 85 classified findings (100%) have no policy gate detected, and the 9 unique entrypoints traced to sensitive operations confirm that SuperAGI's LangChain tool execution layer has no authorization boundary between tool invocation and sensitive operation execution.
3. The email sending surface (`send_email.py`, `send_email_attachment.py`) is doubly exposed: both appear as WARNING findings with instruction-influenced input traced to `smtp.send_message`, and both also appear as HIGH_RISK_UNTRACED unclassified CEEs, meaning outbound email dispatch is reachable from the agent without any detected gate.
4. The marketplace installation pathway (`handleAddTool`, `installFromMarketplace`, `handleInstallClick`) contributes 3 WARNING-level network findings via `api.post` and `api.put`, confirming that the tool installation surface is itself ungoverned -- a supply chain risk where a malicious marketplace tool can be installed without authorization validation and subsequently executed in the same ungoverned environment as built-in tools.
5. Google Calendar mutation operations (create, delete, list, get event) are all ungoverned with tool-controlled input traced into calendar insert operations, making the agent capable of freely modifying a user's primary calendar in response to instruction content without confirmation.
6. The low entrypoint trace count (9) relative to the 40 unclassified CEEs and 966 coverage gap edges means the scan substantially underestimates the sensitive operation reachability; the 8 MEDIUM_RISK_UNTRACED file operation tools in particular are likely to have filesystem paths that were not resolved.
