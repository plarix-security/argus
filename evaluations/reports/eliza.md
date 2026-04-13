# Wyscan Security Report: Eliza

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/elizaOS/eliza
> **Framework(s) detected:** export-entry, action-object, runtime-composition, service-class

## About This System

Eliza is a TypeScript-based multi-agent simulation and social AI framework originally designed for autonomous social media presence. It powers AI agents that interact on Twitter/X, Discord, Telegram, and other platforms, with built-in memory, plugin architecture, and character-based personas. Selected for evaluation because it is deployed at scale in social media environments where adversarial prompt injection through public posts is trivially achievable, and its plugin system grants agents broad API access with minimal governance.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 513 |
| Scan duration | 39.4s |
| Total CEEs detected | 198 |
| Classified findings | 100 |
| Unclassified CEEs | 98 |
| Unique entrypoints reaching sensitive ops | 140 |
| Unresolved call edges (coverage gap) | 10,399 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| WARNING | 78 |
| INFO | 20 |
| UNCLASSIFIED | 98 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

Every single traced path from a tool entry point to a sensitive operation -- process execution, memory writes, network fetches, and filesystem access -- proceeds without any detected authorization check or policy gate. In a social media agent framework where external content is continuously ingested as instruction context, the absence of any policy layer between ingested content and runtime operations makes prompt injection directly actionable. The `createRuntimes` tool's ability to invoke `Bun.spawn` without constraint represents the most severe instance of this pattern, as it exposes arbitrary process execution to the agent's full plugin-controlled input surface.

---

## Critical Findings

### [createRuntimes] -> [Bun.spawn] (instance 1)

| Field | Value |
|-------|-------|
| File | `plugin.ts:45:17` |
| Entry point | `runtime-composition.ts:308` |
| Framework | export-entry |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | No |
| Resource hint | `process` |

**Code:**
```
Bun.spawn
```

**Risk:** The `createRuntimes` export-entry reaches `Bun.spawn` through 5 intermediate calls with no policy gate anywhere in the path. Unresolved edges including `<unknown>`, `pluginNames.add`, and `pluginInput.push` indicate that plugin-controlled data feeds into this execution chain. In a framework that loads plugins dynamically from social media-ingested character definitions, this creates a path from adversarial prompt content to process spawning.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

### [createRuntimes] -> [Bun.spawn] (instance 2)

| Field | Value |
|-------|-------|
| File | `plugin.ts:69:18` |
| Entry point | `runtime-composition.ts:308` |
| Framework | export-entry |
| Operation type | PROCESS_EXECUTION |
| Tool-controlled input | No |
| Instruction-influenced | No |
| Resource hint | `process` |

**Code:**
```
Bun.spawn
```

**Risk:** A second distinct call site in `plugin.ts` reaches `Bun.spawn` from the same `createRuntimes` entry point through the same 5-call chain with identical unresolved edges. Two ungoverned process execution paths from a single plugin-loading entry point doubles the exploitable surface for privilege escalation through plugin manipulation. Both sites share the same unresolved `pluginInput.push` edge, suggesting the input surface is common to both paths.

**AFB04 classification:** Unauthorized Action -- PROCESS_EXECUTION

---

## Warning Findings

### NETWORK (5 findings)

Network fetch operations are reachable from plugin loading and attachment processing tools without any policy gate. The `loadPlugin` and `loadWasmPlugin` tools fetch remote content via `fetch` to load plugin manifests and WASM binaries, while `processAttachments` fetches arbitrary URLs from message content. The combination of manifest-fetching during plugin load and URL-fetching from message attachments creates a bidirectional network access surface with no authorization boundary.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| loadPlugin | export-entry | index.ts:130:27 | -- | No |
| loadWasmPlugin | export-entry | wasm-loader.ts:156:27 | -- | No |
| validateWasmPlugin | export-entry | wasm-loader.ts:156:27 | -- | No |
| loadWasmPlugin | export-entry | wasm-loader.ts:276:27 | -- | No |
| processAttachments | export-entry | index.ts:230:22 | -- | No |
| processAttachments | export-entry | index.ts:345:21 | -- | No |

---

### MEMORY_WRITE -- runtime.createMemory (20 findings)

`runtime.createMemory` is reachable from action handlers and evaluators across follow/unfollow, mute/unmute, autonomy, and follow-up service paths without any policy gate. These writes persist agent state to the long-term memory store in response to social media events, meaning adversarially crafted posts on monitored platforms can drive persistent memory mutations. The evaluators `reflection.ts` and long-term extraction paths also reach `runtime.createMemory` directly from their handlers.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| _shouldFollow | runtime-composition | followRoom.ts:105:10 | -- | No |
| followRoomAction.handler | runtime-composition | followRoom.ts:105:10 | -- | No |
| _shouldFollow | runtime-composition | followRoom.ts:129:10 | -- | No |
| followRoomAction.handler | runtime-composition | followRoom.ts:129:10 | -- | No |
| followRoomAction.handler | runtime-composition | followRoom.ts:178:10 | -- | No |
| _shouldMute | runtime-composition | muteRoom.ts:90:10 | -- | No |
| muteRoomAction.handler | runtime-composition | muteRoom.ts:90:10 | -- | No |
| _shouldMute | runtime-composition | muteRoom.ts:113:10 | -- | No |
| muteRoomAction.handler | runtime-composition | muteRoom.ts:113:10 | -- | No |
| muteRoomAction.handler | runtime-composition | muteRoom.ts:161:10 | -- | No |
| unfollowRoomAction.handler | runtime-composition | unfollowRoom.ts:86:10 | -- | No |
| unfollowRoomAction.handler | runtime-composition | unfollowRoom.ts:151:9 | -- | No |
| _shouldUnmute | runtime-composition | unmuteRoom.ts:68:10 | -- | No |
| unmuteRoomAction.handler | runtime-composition | unmuteRoom.ts:68:10 | -- | No |
| _shouldUnmute | runtime-composition | unmuteRoom.ts:93:10 | -- | No |
| unmuteRoomAction.handler | runtime-composition | unmuteRoom.ts:93:10 | -- | No |
| unmuteRoomAction.handler | runtime-composition | unmuteRoom.ts:177:10 | -- | No |
| handler (reflection) | runtime-composition | reflection.ts:573:7 | -- | No |
| sendToAdminAction.handler | action-object | action.ts:206:8 | -- | No |
| runAutonomyPostResponse | runtime-composition | execution-facade.ts:117:8 | -- | No |
| worker.execute | action-object | followUp.ts:398:11 | -- | No |

---

### MEMORY_WRITE / STATE -- runtime.useModel (30 findings)

`runtime.useModel` is reachable from the majority of action handlers in the advanced-capabilities, advanced-memory, basic-capabilities, and autonomy packages without any policy gate. Every action that invokes the language model -- reply, image generation, role updates, contact management, settings changes, knowledge search, and evaluators -- does so ungoverned. This means instruction-like content from monitored social media channels flows directly into model invocations without a policy checkpoint.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| addContactAction.handler | action-object | addContact.ts:104:25 | runtime | No |
| createTaskAction.handler | action-object | createTask.ts:153:11 | runtime | No |
| _shouldFollow | runtime-composition | followRoom.ts:89:26 | runtime | No |
| followRoomAction.handler | runtime-composition | followRoom.ts:89:26 | runtime | No |
| generateImageAction.handler | action-object | imageGeneration.ts:69:31 | runtime | No |
| generateImageAction.handler | action-object | imageGeneration.ts:82:30 | runtime | No |
| _shouldMute | runtime-composition | muteRoom.ts:74:26 | runtime | No |
| muteRoomAction.handler | runtime-composition | muteRoom.ts:74:26 | runtime | No |
| removeContactAction.handler | action-object | removeContact.ts:78:26 | runtime | No |
| updateRoleAction.handler | action-object | roles.ts:277:25 | runtime | No |
| scheduleFollowUpAction.handler | action-object | scheduleFollowUp.ts:104:25 | runtime | No |
| searchContactsAction.handler | action-object | searchContacts.ts:104:25 | runtime | No |
| sendMessageAction.handler | action-object | sendMessage.ts:277:30 | runtime | No |
| updateSettingsAction.handler | action-object | settings.ts:525:24 | runtime | No |
| updateSettingsAction.handler | action-object | settings.ts:590:24 | runtime | No |
| updateSettingsAction.handler | action-object | settings.ts:654:24 | runtime | No |
| updateSettingsAction.handler | action-object | settings.ts:696:24 | runtime | No |
| thinkAction.handler | action-object | think.ts:72:25 | runtime | No |
| unfollowRoomAction.handler | runtime-composition | unfollowRoom.ts:50:26 | runtime | No |
| _shouldUnmute | runtime-composition | unmuteRoom.ts:51:26 | runtime | No |
| unmuteRoomAction.handler | runtime-composition | unmuteRoom.ts:51:26 | runtime | No |
| updateContactAction.handler | action-object | updateContact.ts:100:26 | runtime | No |
| updateEntityAction.handler | action-object | updateEntity.ts:305:23 | runtime | No |
| handler (reflection evaluator) | runtime-composition | reflection.ts:658:24 | runtime | No |
| longTermExtractionEvaluator.handler | action-object | long-term-extraction.ts:197:26 | runtime | No |
| handler (advanced-memory reflection) | runtime-composition | reflection.ts:423:24 | runtime | No |
| summarizationEvaluator.handler | action-object | summarization.ts:257:26 | runtime | No |
| scheduleFollowUpAction.handler | action-object | scheduleFollowUp.ts:196:25 | runtime | No |
| choiceAction.handler | action-object | choice.ts:161:23 | runtime | No |
| replyAction.handler | action-object | reply.ts:70:25 | runtime | No |
| processAttachments | export-entry | index.ts:244:21 | runtime | No |
| generateTextEmbedding | export-entry | llm.ts:109:25 | runtime | No |
| trimTokens | export-entry | utils.ts:1031:22 | runtime | No |
| trimTokens | export-entry | utils.ts:1045:14 | runtime | No |

---

### FILESYSTEM (15 findings)

Filesystem operations (`fs.mkdirSync`, `sha1Cache.delete`, `visiting.delete`, `registry.delete`) are reachable from multiple action and export-entry tools. The `logger.ts:407` `fs.mkdirSync` path is reached from 8 distinct entry points including `createTaskAction.handler`, `processKnowledgeAction.handler`, `searchKnowledgeAction.handler`, `generateText`, and `createRuntimes`. Cache and registry deletion operations in `utils.ts` and `task-scheduler.ts` are also ungoverned. Cross-file paths through the logger indicate the filesystem exposure is systemic rather than localized.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| createTaskAction.handler | action-object | logger.ts:407:2 | directory | No |
| processKnowledgeAction.handler | action-object | logger.ts:407:2 | directory | No |
| searchKnowledgeAction.handler | action-object | logger.ts:407:2 | directory | No |
| generateTextEmbedding | export-entry | logger.ts:407:2 | directory | No |
| generateText | export-entry | logger.ts:407:2 | directory | No |
| start (knowledge service) | service-class | logger.ts:407:2 | directory | No |
| createRuntimes | export-entry | logger.ts:407:2 | directory | No |
| worker.execute | action-object | logger.ts:407:2 | directory | No |
| createRuntimes | export-entry | plugin.ts:313:2 | http | No |
| unregisterTaskSchedulerRuntime | export-entry | task-scheduler.ts:101:1 | http | No |
| createTaskAction.handler | action-object | utils.ts:1218:3 | http | No |
| sendToAdminAction.handler | action-object | utils.ts:1218:3 | http | No |
| runAutonomyPostResponse | runtime-composition | utils.ts:1218:3 | http | No |
| processKnowledgeAction.handler | action-object | utils.ts:1218:3 | http | No |
| loadCharacters | export-entry | utils.ts:1218:3 | http | No |
| createRuntimes | export-entry | utils.ts:1218:3 | http | No |
| worker.execute | action-object | utils.ts:1218:3 | http | No |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| loadPlugin | export-entry | index.ts:127:26 | fs.readFile | file |
| loadPlugin | export-entry | wasm-loader.ts:137:23 | fs.stat | file |
| loadWasmPlugin | export-entry | wasm-loader.ts:137:23 | fs.stat | file |
| validateWasmPlugin | export-entry | wasm-loader.ts:137:23 | fs.stat | file |
| loadPlugin | export-entry | wasm-loader.ts:144:29 | fs.readFile | file |
| loadWasmPlugin | export-entry | wasm-loader.ts:144:29 | fs.readFile | file |
| validateWasmPlugin | export-entry | wasm-loader.ts:144:29 | fs.readFile | file |
| loadPlugin | export-entry | wasm-loader.ts:273:26 | fs.readFile | file |
| loadWasmPlugin | export-entry | wasm-loader.ts:273:26 | fs.readFile | file |
| processKnowledgeAction.handler | action-object | actions.ts:167:9 | fs.existsSync | file |
| processKnowledgeAction.handler | action-object | actions.ts:178:23 | fs.readFileSync | file |
| loadCharacters | export-entry | runtime-composition.ts:254:22 | readFile | -- |
| migrateAllChannels | export-entry | pairing-migration.ts:343:30 | readFile | -- |
| migrateFromFileSystem | export-entry | pairing-migration.ts:343:30 | readFile | -- |
| migrateAllChannels | export-entry | pairing-migration.ts:352:32 | readFile | -- |
| migrateFromFileSystem | export-entry | pairing-migration.ts:352:32 | readFile | -- |
| migrateAllChannels | export-entry | pairing-migration.ts:429:9 | fs.readFile | file |
| migrateFromFileSystem | export-entry | pairing-migration.ts:429:9 | fs.readFile | file |
| migrateAllChannels | export-entry | pairing-migration.ts:434:25 | fs.readdir | directory |
| migrateFromFileSystem | export-entry | pairing-migration.ts:434:25 | fs.readdir | directory |

---

## Unclassified CEEs

**Total:** 98

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (0):**
None.

**LOW_RISK_UNTRACED tools (98):**
All 98 unclassified CEEs are low-risk by function name. They consist primarily of framework lifecycle hooks and event handlers (ACTION_STARTED, ACTION_COMPLETED, EVALUATOR_STARTED, RUN_STARTED, RUN_ENDED, RUN_TIMEOUT, CONTROL_MESSAGE, WORLD_JOINED, MESSAGE_SENT, etc.), service start methods (approval.ts, followUp.ts, hook.ts, embedding.ts, pairing.ts, relationships.ts, task.ts, tool-policy.ts, triggerWorker.ts), utility functions (formatMessages, splitChunks, truncateToCompleteSentence, prewarmUuidCache), infrastructure functions (provisionAgent, ensureAgentInfrastructure, runPluginMigrations), and plugin-loading helpers (installRuntimePluginLifecycle, loadPythonPlugin, stopPythonPlugin). The high volume of unresolved event handler registrations in Discord/Telegram client code (index.ts) contributes significantly to this count.

---

## Coverage Gap Analysis

**Unresolved call edges:** 10,399
**Unique entrypoints traced to sensitive ops:** 140

The coverage gap of 10,399 unresolved edges is extremely large relative to the 513 files scanned, reflecting the complexity of Eliza's dynamic plugin architecture where plugins are loaded at runtime via manifest resolution, WASM instantiation, and Python bridge interop. The scan flagged 1 file as failed to analyze, and the frequent appearance of `<unknown>` as an unresolved edge in critical paths (both `Bun.spawn` findings include `<unknown>`) means the actual process execution exposure may be broader than what was traced. The 140 unique entrypoints reaching sensitive operations is a high count that confirms the authorization gap is systemic rather than confined to a few isolated paths.

---

## Key Findings Summary

1. Both CRITICAL findings share the same entry point (`createRuntimes`) and the same destination (`Bun.spawn`), establishing that the plugin loading system provides an ungoverned path to arbitrary process execution reachable from Eliza's runtime initialization surface.
2. All 100 classified findings (100%) have no policy gate detected, confirming the framework operates in a fully ungoverned state with respect to sensitive operation authorization -- no finding in the entire scan passed through a recognized policy checkpoint.
3. The 30 `runtime.useModel` WARNING findings span the full breadth of agent action types including role management, settings mutation, contact operations, and autonomous follow-up scheduling, meaning adversarial instruction injection from social media content can drive model inference across all of these actions without a gate.
4. The 20 `runtime.createMemory` WARNING findings confirm that content-driven memory poisoning is possible across follow/unfollow, mute/unmute, autonomy, and follow-up execution paths, enabling persistent state corruption from external social media inputs.
5. The `fs.mkdirSync` path through `logger.ts:407` is reached from 8 distinct entry points via cross-file call chains, indicating that filesystem write access is a secondary consequence of normal operational paths (logging) rather than an explicit design decision, and is therefore unlikely to be audited or gated.
6. The 10,399 unresolved call edges mean the true scope of sensitive operation reachability is substantially underreported; given the dynamic plugin system and 98 unclassified CEEs, additional ungoverned paths almost certainly exist beyond what static analysis resolved.
