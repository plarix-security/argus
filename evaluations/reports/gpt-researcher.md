# Wyscan Security Report: GPT Researcher

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/assafelovic/gpt-researcher
> **Framework(s) detected:** langchain

## About This System

GPT Researcher is an autonomous research agent designed to perform comprehensive online research on any topic and produce detailed, factual reports. It orchestrates web search, content scraping, and synthesis across multiple sources using LangChain. It was selected for AFB04 evaluation because it is a high-volume web-facing agent that autonomously fetches and processes arbitrary external content, making it a prime target for prompt injection via poisoned web pages or search results.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 278 |
| Scan duration | 3.9s |
| Total CEEs detected | 40 |
| Classified findings | 3 |
| Unclassified CEEs | 37 |
| Unique entrypoints reaching sensitive ops | 34 |
| Unresolved call edges (coverage gap) | 2322 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| WARNING | 0 |
| INFO | 3 |
| UNCLASSIFIED | 37 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

All 3 classified findings share the same ungoverned call path from the `search_tool` LangChain tool into `result.get` operations in `tools.py`, where title, content, and URL fields from external search results are read without any policy gate. The more significant concern is structural: 34 unique entrypoints were traced to sensitive operations and 37 CEEs remain unclassified, meaning the classified surface (3 INFO findings) dramatically understates actual exposure. The 2322 unresolved call edges -- the largest coverage gap of any system evaluated -- indicate extensive dynamic dispatch through LangChain internals and web-scraping libraries that static analysis could not fully traverse.

---

## Critical Findings

No CRITICAL findings detected.

---

## Warning Findings

No WARNING findings detected.

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| search_tool | langchain | tools.py:216 | MEMORY_READ | title |
| search_tool | langchain | tools.py:217 | MEMORY_READ | content |
| search_tool | langchain | tools.py:218 | MEMORY_READ | url |

---

## Unclassified CEEs

**Total:** 37

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (1):**
- `sendChatMessage` -- `scripts.js:1893`

**LOW_RISK_UNTRACED tools (36):**
36 entries covering UI event handlers, workbox service worker internals, and frontend utility functions. Named entries include: `Home` (page.tsx:28), `checkIfMobile` (page.tsx:84, page.tsx:312, CopilotResearchContent.tsx:67, getLayout.tsx:44), `handleScroll` (Hero.tsx:62), `handleKeyDown` (ImageModal.tsx:17), `startLanggraphResearch` (Langgraph.js:4), `handleResizeMove` (CopilotResearchContent.tsx:142), `handleResizeEnd` (CopilotResearchContent.tsx:177), `handleClickOutside` (ResearchSidebar.tsx:28), `i` and `r` (workbox-f1770938.js:1, x4), `init` (scripts.js:25), `initHistoryPanel` (scripts.js:107), `initWebSocketPanel` (scripts.js:215), `clearConversationHistory` (scripts.js:492), `filterHistoryEntries` (scripts.js:502), `copyToClipboard` (scripts.js:1142), `showImageDialog` (scripts.js:1351), `escapeKeyListener` (scripts.js:1384), `checkCookieStatus` (scripts.js:1528), `exportHistory` (scripts.js:1577), `triggerImportHistory` (scripts.js:1620), `handleFileImport` (scripts.js:1630), `initChat` (scripts.js:1712), `initSpeechRecognition` (scripts.js:1751), `initExpandButtons` (scripts.js:2011), `initMCPSection` (scripts.js:2114), `validateMCPConfig` (scripts.js:2177), `formatMCPConfig` (scripts.js:2228), `showMCPInfo` (scripts.js:2279), `createMCPInfoModal` (scripts.js:2287), `custom_tool` (tools.py:260).

---

## Coverage Gap Analysis

**Unresolved call edges:** 2322
**Unique entrypoints traced to sensitive ops:** 34

2322 unresolved call edges against 278 files represents a ratio of approximately 8.4 unresolved edges per file -- the highest density of any system in this evaluation set. This indicates that GPT Researcher's heavy reliance on LangChain's internal orchestration, web scraping libraries (likely BeautifulSoup, httpx, or similar), and dynamic content processing creates a call graph that static analysis cannot adequately traverse. The 34 unique entrypoints successfully traced to sensitive operations represents meaningful depth of coverage, but the 37 unclassified CEEs and the vast unresolved edge count mean that the 3 INFO findings are almost certainly a floor, not a ceiling, for actual sensitive operation exposure.

---

## Key Findings Summary

1. No CRITICAL or WARNING findings were classified, but this is a product of coverage limitations rather than system safety: 2322 unresolved call edges mean the majority of GPT Researcher's execution paths -- particularly its web scraping and content processing pipeline -- were not traversable by static analysis.
2. The 3 INFO findings confirm that `search_tool` reads title, content, and URL fields from external search results (`tools.py:216-218`) with no policy gate, establishing that externally sourced content flows unfiltered into the agent's context -- the primary prompt injection surface for this system.
3. 34 unique entrypoints were traced to sensitive operations, the highest count in this evaluation set, indicating a wide and deeply connected tool surface that warrants dynamic or manual analysis to complement static findings.
4. `custom_tool` at `tools.py:260` is an unclassified CEE -- its existence as a named registration point for user-defined tools means arbitrary external operations can be registered without Wyscan tracing their execution path.
5. `sendChatMessage` at `scripts.js:1893` is a MEDIUM_RISK_UNTRACED unclassified CEE; if this function transmits research output or user input to an external endpoint, it represents an ungoverned data exfiltration path.
6. The combination of autonomous web content fetching, 37 unclassified CEEs, and 2322 unresolved edges makes GPT Researcher the system in this evaluation with the largest unknown attack surface -- a dynamic analysis pass is strongly recommended to surface operations hidden behind LangChain dispatch and scraping library boundaries.
