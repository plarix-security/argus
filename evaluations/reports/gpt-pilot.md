# Wyscan Security Report: GPT Pilot

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/Pythagora-io/gpt-pilot
> **Framework(s) detected:** class-based-tool

## About This System

GPT Pilot is an AI coding assistant that autonomously builds full-stack applications step-by-step in collaboration with a human developer. It decomposes application specs, writes code, runs tests, debugs failures, and interacts with the developer for clarification or approval at key decision points. Selected for evaluation because it executes code in developer environments with direct shell access, making any authorization gap in its tool call path a potential vector for supply-chain compromise or arbitrary code execution in the developer's local environment.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 302 |
| Scan duration | 12.9s |
| Total CEEs detected | 232 |
| Classified findings | 209 |
| Unclassified CEEs | 23 |
| Unique entrypoints reaching sensitive ops | 4 |
| Unresolved call edges (coverage gap) | 379 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| WARNING | 88 |
| INFO | 121 |
| UNCLASSIFIED | 23 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

Every classified finding in the GPT Pilot scan reports no policy gate detected in the analyzed call path. The system's entire agent population -- architect, developer, bug hunter, orchestrator, frontend, and others -- share a single class-based-tool entrypoint pattern (`run`) with no interposed authorization layer. Tool-controlled input and instruction-influenced data flow into network calls, state mutation, and telemetry collection without any approval checkpoint, making the developer's local environment a fully exposed execution surface.

---

## Critical Findings

No CRITICAL findings detected.

---

## Warning Findings

### NETWORK (14 findings)

Fourteen warning findings trace the `run` tool entrypoint through to outbound HTTP calls -- `httpx.Client.get`, `client.post`, and `httpx.AsyncClient.post` -- across agents including `external_docs.py`, `frontend.py`, `wizard.py`, and a cross-file path through `__init__.py`. Nine of these cross file boundaries and carry instruction-influenced input. The `self.endpoint` resource hint on the nine `__init__.py:387` findings indicates that the POST destination URL itself is reachable from agent context, enabling server-side request forgery if an adversarial instruction supplies a crafted endpoint.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| run | class-based-tool | external_docs.py:76 | url | No |
| run | class-based-tool | external_docs.py:143 | url | No |
| run | class-based-tool | frontend.py:248 | url | No |
| run | class-based-tool | frontend.py:470 | url | No |
| run | class-based-tool | wizard.py:142 | url | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |
| run | class-based-tool | __init__.py:387 | self.endpoint | No |

### COMMUNICATION / STATE_MUTATION (74 findings)

The dominant warning pattern is `self.send_message` and `self.ui.send_message` called from every agent's `run` entrypoint with no policy gate. These calls propagate LLM-generated strings, instruction-influenced content, task descriptions, and user feedback directly to the UI channel. Affected agents include `architect.py`, `bug_hunter.py`, `developer.py`, `executor.py`, `frontend.py`, `human_input.py`, `importer.py`, `orchestrator.py`, `tech_lead.py`, `tech_writer.py`, `troubleshooter.py`, and `wizard.py`. Several findings also flag `.append()` calls on state collections (`async_tasks`, `unique_steps`, `epic_tasks`, `tasks`, `parallel`, `input_required_files`, `file_paths_to_remove_mock`) as ungoverned state mutation reachable from tool invocation with instruction-influenced input.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| run | class-based-tool | architect.py:110 | templates | No |
| run | class-based-tool | architect.py:135 | Selecting starter templates ... | No |
| run | class-based-tool | architect.py:174 | Planning project architecture ... | No |
| run | class-based-tool | architect.py:177 | Picking technologies to use ... | No |
| run | class-based-tool | architect.py:197 | architecture | No |
| run | class-based-tool | architect.py:235 | templates | No |
| run | class-based-tool | architect.py:249 | f"Checking if {dep['name']} is available ..." | No |
| run | class-based-tool | architect.py:257 | f"[X] {dep['name']} is not available. {remedy}" | No |
| run | class-based-tool | architect.py:266 | f"[OK] {dep['name']} is available." | No |
| run | class-based-tool | bug_hunter.py:67 | (none) | No |
| run | class-based-tool | bug_hunter.py:83 | Finding a way to reproduce the bug ... | No |
| run | class-based-tool | bug_hunter.py:132 | Found the bug. I'm attempting to fix it ... | No |
| run | class-based-tool | bug_hunter.py:137 | Adding more logs to identify the bug ... | No |
| run | class-based-tool | bug_hunter.py:157 | Start the app and test it by following these instructions:\n\n | No |
| run | class-based-tool | bug_hunter.py:320 | llm_answer | No |
| run | class-based-tool | bug_hunter.py:325 | response | No |
| run | class-based-tool | bug_hunter.py:332 | llm_answer | No |
| run | class-based-tool | bug_hunter.py:358 | response | No |
| run | class-based-tool | bug_hunter.py:396 | Waiting for the bug reproduction instructions... | No |
| run | class-based-tool | code_monkey.py:181 | file | No |
| run | class-based-tool | developer.py:228 | ### Thinking about how to implement this task ... | No |
| run | class-based-tool | developer.py:339 | step | No |
| run | class-based-tool | developer.py:415 | f"Starting task #{task_index} with the description:\n\n## {description}" | No |
| run | class-based-tool | developer.py:420 | f"Additional feedback: {self.next_state.current_task['redo_human_instructions']}" | No |
| run | class-based-tool | developer.py:433 | Ok, great, you're now starting to build the backend ... | No |
| run | class-based-tool | developer.py:453 | Skipping task... | No |
| run | class-based-tool | executor.py:96 | f"Skipping command {cmd}" | No |
| run | class-based-tool | external_docs.py:101 | Determining if external documentation is needed... | No |
| run | class-based-tool | external_docs.py:113 | Getting relevant documentation for the following topics: | No |
| run | class-based-tool | external_docs.py:143 | url | No |
| run | class-based-tool | external_docs.py:144 | docset_key | No |
| run | class-based-tool | external_docs.py:155 | k | No |
| run | class-based-tool | external_docs.py:171 | docset_key | No |
| run | class-based-tool | frontend.py:78 | ## Building the frontend\n\nThis may take a couple of minutes. | No |
| run | class-based-tool | frontend.py:119 | ### Continuing to build UI... This may take a couple of minutes. | No |
| run | class-based-tool | frontend.py:169 | Errors detected, fixing... | No |
| run | class-based-tool | frontend.py:229 | Implementing the changes you suggested... | No |
| run | class-based-tool | frontend.py:266 | f"Couldn't find any relevant API documentation. Retrying... \nError: {error}" | No |
| run | class-based-tool | frontend.py:275 | f"Please try reloading the project. \nError: {error}" | No |
| run | class-based-tool | frontend.py:404 | file_path | No |
| run | class-based-tool | frontend.py:444 | f"Running command: `{command}`..." | No |
| run | class-based-tool | frontend.py:507 | f"I couldn't find any relevant API documentation. Retrying... \nError: {error}" | No |
| run | class-based-tool | frontend.py:514 | f"Please try reloading the project. \nError: {error}" | No |
| run | class-based-tool | frontend.py:564 | f"### Auto-debugging the frontend #{...}" | No |
| run | class-based-tool | frontend.py:594 | f"### Auto-debugging found an error: \n{diff_stdout}\n{diff_stderr}" | No |
| run | class-based-tool | frontend.py:601 | ### All good, no errors found. | No |
| run | class-based-tool | human_input.py:19 | f"## {HUMAN_INTERVENTION_QUESTION}\n\n{description}" | No |
| run | class-based-tool | importer.py:34 | f"This is experimental feature and is currently limited to projects with size up to {MAX_PROJECT_LINES} lines of code." | No |
| run | class-based-tool | importer.py:51 | WARNING: Your project ({imported_lines} LOC) is larger than supported ... | No |
| run | class-based-tool | importer.py:59 | Inspecting most important project files ... | No |
| run | class-based-tool | importer.py:65 | Analyzing project ... | No |
| run | class-based-tool | orchestrator.py:179 | Installing project dependencies... | No |
| run | class-based-tool | orchestrator.py:388 | f"We found {len(modified_files)} new and/or modified files." | No |
| run | class-based-tool | orchestrator.py:560 | self.state_manager | No |
| run | class-based-tool | orchestrator.py:588 | file.path | No |
| run | class-based-tool | orchestrator.py:637 | num_files | No |
| run | class-based-tool | orchestrator.py:638 | num_lines | No |
| run | class-based-tool | tech_lead.py:148 | Your new feature is complete! | No |
| run | class-based-tool | tech_lead.py:156 | Your app is DONE! You can start using it right now! | No |
| run | class-based-tool | tech_lead.py:182 | Thank you for using Pythagora! | No |
| run | class-based-tool | tech_lead.py:299 | Creating the development plan ... | No |
| run | class-based-tool | tech_lead.py:322 | Creating tasks ... | No |
| run | class-based-tool | tech_lead.py:342 | sub_epic_number | No |
| run | class-based-tool | tech_lead.py:347 | tasks_result | No |
| run | class-based-tool | tech_lead.py:388 | Implement and test Login and Register pages. | No |
| run | class-based-tool | tech_writer.py:42 | f"CONGRATULATIONS! You reached {pct_finished}% of your project generation!" | No |
| run | class-based-tool | tech_writer.py:54 | Creating README ... | No |
| run | class-based-tool | troubleshooter.py:79 | Test the app by following these steps: | No |
| run | class-based-tool | troubleshooter.py:191 | Figuring out how to run the app ... | No |
| run | class-based-tool | troubleshooter.py:204 | ### Determining how to test the app ... | No |
| run | class-based-tool | troubleshooter.py:223 | No testing required for this task, moving on to the next one. | No |
| run | class-based-tool | wizard.py:51 | Please try creating a new project. | No |
| run | class-based-tool | wizard.py:57 | Please provide a valid input. | No |
| run | class-based-tool | wizard.py:109 | Thank you for submitting your request. We will be in touch. | No |
| run | class-based-tool | wizard.py:171 | f"An error occurred while uploading the docs. Error: {error if error else 'unknown'}" | No |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| run | class-based-tool | bug_hunter.py:127 | MEMORY_READ | bug_hunting_cycles |
| run | class-based-tool | bug_hunter.py:372 | MEMORY_READ | test_instructions |
| run | class-based-tool | bug_hunter.py:375 | MEMORY_READ | bug_hunting_cycles |
| run | class-based-tool | bug_hunter.py:382 | MEMORY_READ | backend_logs |
| run | class-based-tool | bug_hunter.py:383 | MEMORY_READ | frontend_logs |
| run | class-based-tool | bug_hunter.py:384 | MEMORY_READ | fix_attempted |
| run | class-based-tool | bug_hunter.py:385 | MEMORY_READ | user_feedback |
| run | class-based-tool | code_monkey.py:109 | MEMORY_READ | description |
| run | class-based-tool | code_monkey.py:110 | MEMORY_READ | user_feedback |
| run | class-based-tool | code_monkey.py:111 | MEMORY_READ | user_feedback_qa |
| run | class-based-tool | code_monkey.py:165 | MEMORY_READ | description |
| run | class-based-tool | code_monkey.py:169 | MEMORY_READ | file.path |
| run | class-based-tool | developer.py:96 | MEMORY_READ | type |
| run | class-based-tool | developer.py:110 | MEMORY_READ | run_always |
| run | class-based-tool | developer.py:209 | MEMORY_READ | source |
| run | class-based-tool | developer.py:232 | MEMORY_READ | related_api_endpoints |
| run | class-based-tool | developer.py:247 | MEMORY_READ | redo_human_instructions |
| run | class-based-tool | developer.py:395 | MEMORY_READ | id |
| run | class-based-tool | developer.py:402 | MEMORY_READ | id |
| run | class-based-tool | developer.py:419 | MEMORY_READ | redo_human_instructions |
| run | class-based-tool | developer.py:423 | MEMORY_READ | quick_implementation |
| run | class-based-tool | developer.py:426 | MEMORY_READ | user_added_subsequently |
| run | class-based-tool | developer.py:429 | MEMORY_READ | hardcoded |
| run | class-based-tool | developer.py:432 | MEMORY_READ | hardcoded |
| run | class-based-tool | error_handler.py:45 | MEMORY_READ | message |
| run | class-based-tool | error_handler.py:67 | MEMORY_READ | cmd |
| run | class-based-tool | error_handler.py:68 | MEMORY_READ | timeout |
| run | class-based-tool | error_handler.py:69 | MEMORY_READ | status_code |
| run | class-based-tool | error_handler.py:70 | MEMORY_READ | stdout |
| run | class-based-tool | error_handler.py:71 | MEMORY_READ | stderr |
| run | class-based-tool | error_handler.py:119 | MEMORY_READ | completed |
| run | class-based-tool | executor.py:79 | MEMORY_READ | timeout |
| run | class-based-tool | external_docs.py:143 | NETWORK | url |
| run | class-based-tool | frontend.py:47 | MEMORY_READ | file_paths_to_remove_mock |
| run | class-based-tool | frontend.py:51 | MEMORY_READ | fe_iteration_done |
| run | class-based-tool | frontend.py:132 | MEMORY_READ | use_relace |
| run | class-based-tool | frontend.py:135 | MEMORY_READ | manual_iteration |
| run | class-based-tool | frontend.py:138 | MEMORY_READ | retry_count |
| run | class-based-tool | frontend.py:140 | MEMORY_READ | retry_count |
| run | class-based-tool | frontend.py:402 | MEMORY_READ | file_paths_to_remove_mock |
| run | class-based-tool | frontend.py:436 | FILESYSTEM | absolute_path |
| run | class-based-tool | frontend.py:438 | MEMORY_READ | scripts |
| run | class-based-tool | frontend.py:558 | MEMORY_READ | auto_debug_attempts |
| run | class-based-tool | frontend.py:568 | MEMORY_READ | auto_debug_attempts |
| run | class-based-tool | human_input.py:12 | MEMORY_READ | files |
| run | class-based-tool | orchestrator.py:91 | MEMORY_READ | redo_human_instructions |
| run | class-based-tool | orchestrator.py:118 | MEMORY_READ | path |
| run | class-based-tool | orchestrator.py:118 | MEMORY_READ | save_file |
| run | class-based-tool | orchestrator.py:119 | MEMORY_READ | path |
| run | class-based-tool | orchestrator.py:119 | MEMORY_READ | save_file |
| run | class-based-tool | orchestrator.py:120 | MEMORY_READ | related_api_endpoints |
| run | class-based-tool | orchestrator.py:127 | MEMORY_READ | path |
| run | class-based-tool | orchestrator.py:127 | MEMORY_READ | save_file |
| run | class-based-tool | orchestrator.py:128 | MEMORY_READ | content |
| run | class-based-tool | orchestrator.py:128 | MEMORY_READ | save_file |
| run | class-based-tool | orchestrator.py:129 | MEMORY_READ | related_api_endpoints |
| run | class-based-tool | orchestrator.py:135 | MEMORY_READ | related_api_endpoints |
| run | class-based-tool | orchestrator.py:172 | FILESYSTEM | package_json_path |
| run | class-based-tool | orchestrator.py:178 | FILESYSTEM | node_modules_path |
| run | class-based-tool | orchestrator.py:188 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:193 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:194 | FILESYSTEM | (none) |
| run | class-based-tool | orchestrator.py:225 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:229 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:260 | FILESYSTEM | index_path |
| run | class-based-tool | orchestrator.py:264 | FILESYSTEM | index_path |
| run | class-based-tool | orchestrator.py:265 | FILESYSTEM | (none) |
| run | class-based-tool | orchestrator.py:287 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:292 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:295 | MEMORY_READ | build |
| run | class-based-tool | orchestrator.py:310 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:315 | FILESYSTEM | absolute_path |
| run | class-based-tool | orchestrator.py:316 | FILESYSTEM | (none) |
| run | class-based-tool | orchestrator.py:335 | FILESYSTEM | template_path |
| run | class-based-tool | orchestrator.py:336 | FILESYSTEM | (none) |
| run | class-based-tool | orchestrator.py:362 | MEMORY_READ | files |
| run | class-based-tool | orchestrator.py:455 | MEMORY_READ | description |
| run | class-based-tool | orchestrator.py:483 | MEMORY_READ | description |
| run | class-based-tool | orchestrator.py:486 | MEMORY_READ | source |
| run | class-based-tool | orchestrator.py:498 | MEMORY_READ | status |
| run | class-based-tool | orchestrator.py:555 | MEMORY_READ | type |
| run | class-based-tool | orchestrator.py:622 | MEMORY_READ | source |
| run | class-based-tool | task_completer.py:24 | MEMORY_READ | source |
| run | class-based-tool | tech_lead.py:235 | MEMORY_READ | description |
| run | class-based-tool | tech_lead.py:256 | MEMORY_READ | sub_epics |
| run | class-based-tool | tech_lead.py:301 | MEMORY_READ | source |
| run | class-based-tool | tech_lead.py:302 | MEMORY_READ | description |
| run | class-based-tool | tech_lead.py:310 | MEMORY_READ | source |
| run | class-based-tool | tech_lead.py:323 | MEMORY_READ | source |
| run | class-based-tool | tech_lead.py:384 | MEMORY_READ | source |
| run | class-based-tool | tech_lead.py:385 | MEMORY_READ | auth |
| run | class-based-tool | troubleshooter.py:41 | MEMORY_READ | status |
| run | class-based-tool | troubleshooter.py:49 | MEMORY_READ | user_feedback |
| run | class-based-tool | troubleshooter.py:50 | MEMORY_READ | user_feedback_qa |
| run | class-based-tool | troubleshooter.py:51 | MEMORY_READ | bug_hunting_cycles |
| run | class-based-tool | troubleshooter.py:66 | MEMORY_READ | test_instructions |
| run | class-based-tool | troubleshooter.py:113 | MEMORY_READ | alternative_solutions |
| run | class-based-tool | troubleshooter.py:166 | MEMORY_READ | related_api_endpoints |
| run | class-based-tool | troubleshooter.py:291 | MEMORY_READ | hardcoded |
| run | class-based-tool | wizard.py:76 | MEMORY_READ | types |
| run | class-based-tool | helpers.py:424 | MEMORY_READ | sub_epic_id |
| run | class-based-tool | api_server.py:281 | MEMORY_READ | description |
| run | class-based-tool | api_server.py:284 | MEMORY_READ | description |
| run | class-based-tool | api_server.py:288 | MEMORY_READ | user_feedback |
| run | class-based-tool | api_server.py:290 | MEMORY_READ | test_instructions |
| run | class-based-tool | api_server.py:291 | MEMORY_READ | test_instructions |
| run | class-based-tool | api_server.py:295 | MEMORY_READ | command |
| run | class-based-tool | api_server.py:296 | MEMORY_READ | completed |
| run | class-based-tool | api_server.py:298 | MEMORY_READ | command |
| run | class-based-tool | api_server.py:298 | MEMORY_READ | command |
| run | class-based-tool | api_server.py:302 | MEMORY_READ | human_intervention_description |
| run | class-based-tool | api_server.py:303 | MEMORY_READ | completed |
| run | class-based-tool | api_server.py:305 | MEMORY_READ | human_intervention_description |
| run | class-based-tool | api_server.py:321 | MEMORY_READ | message |
| run | class-based-tool | api_server.py:325 | MEMORY_READ | role |
| run | class-based-tool | api_server.py:326 | MEMORY_READ | content |
| run | class-based-tool | api_server.py:327 | MEMORY_READ | role |
| run | class-based-tool | api_server.py:328 | MEMORY_READ | content |
| run | class-based-tool | api_server.py:339 | MEMORY_READ | convoId |
| run | class-based-tool | api_server.py:340 | MEMORY_READ | chatHistory |
| run | class-based-tool | text.py:30 | MEMORY_READ | marker |

---

## Unclassified CEEs

**Total:** 23

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (0):**
None.

**LOW_RISK_UNTRACED tools (23):**
All 23 unclassified CEEs are `run` method registrations on class-based agents: `architect.py:99`, `bug_hunter.py:61`, `code_monkey.py:72`, `developer.py:95`, `error_handler.py:24`, `executor.py:72`, `external_docs.py:46`, `frontend.py:44`, `human_input.py:10`, `importer.py:21`, `legacy_handler.py:9`, `orchestrator.py:48`, `problem_solver.py:38`, `task_completer.py:15`, `tech_lead.py:59`, `tech_writer.py:16`, `troubleshooter.py:39`, `wizard.py:24` (18 Python agents), plus `sidebar.tsx:100` (handleKeyDown, x2), `useMobile.tsx:10` (onChange, x2), and `api_server.py:335`. These correspond exactly to the agents whose classified findings appear in the WARNING and INFO sections -- the unclassified registration is the agent class entry point from which all those operations propagate.

---

## Coverage Gap Analysis

**Unresolved call edges:** 379
**Unique entrypoints traced to sensitive ops:** 4

The 379 unresolved call edges against only 302 scanned files indicate a high proportion of dynamic dispatch, cross-module imports, and async task creation that the static call graph could not resolve. Only 4 unique entrypoints were successfully traced to sensitive operations despite 18 Python agent classes being detected, suggesting that the majority of agent execution paths involve indirect call patterns that require runtime analysis to fully characterize. The 23 unclassified tool registrations represent the unresolved tail -- each is a potential additional entrypoint to operations already flagged in the classified set.

---

## Key Findings Summary

1. GPT Pilot has zero CRITICAL findings but 88 WARNING findings, all from a single framework pattern (`class-based-tool` / `run` method) with no policy gate anywhere in the analyzed call graph -- 100% of classified findings are ungoverned.
2. The dominant risk surface is unbounded outbound HTTP: 14 network-reaching warning findings across `external_docs.py`, `frontend.py`, `wizard.py`, and a shared `__init__.py:387` POST path reachable from 9 different agent entrypoints, with instruction-influenced input present in the majority.
3. Instruction-influenced data flows directly into UI message channels (`send_message`, `ui.send_message`) across every agent, creating a prompt-injection surface where adversarial content in LLM responses propagates unfiltered to the developer interface.
4. Telemetry calls (`telemetry.set`) in `architect.py` and `orchestrator.py` receive architecture specs, template names, and file metrics directly from the `run` entrypoint with no policy check, creating a data-exfiltration pathway if the telemetry endpoint is attacker-controlled.
5. The 4 unique entrypoints traced to sensitive ops against 18 agent classes and 379 unresolved edges highlights a substantial coverage gap -- the true attack surface is likely larger than what static analysis resolved.
6. The absence of any process execution findings (no `subprocess`, `os.system`, `exec`) in the classified set is notable; GPT Pilot's shell execution capability likely operates through a different code path that was not resolved by the call graph, representing an unquantified risk not captured in this scan.
