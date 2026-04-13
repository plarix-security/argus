# Wyscan Security Report: AgentGPT

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/reworkd/AgentGPT
> **Framework(s) detected:** langchain

## About This System

AgentGPT is a browser-based autonomous AI agent platform that allows users to configure and deploy AI agents to accomplish arbitrary goals. Built with a React/Next.js frontend and a Python FastAPI backend, it uses LangChain as its agent orchestration layer. It was selected for AFB04 evaluation because it represents a widely-deployed consumer-facing autonomous agent with real network access tools, a public API, and a large non-technical user base unlikely to have visibility into its security posture.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 234 |
| Scan duration | 2.7s |
| Total CEEs detected | 29 |
| Classified findings | 20 |
| Unclassified CEEs | 9 |
| Unique entrypoints reaching sensitive ops | 2 |
| Unresolved call edges (coverage gap) | 563 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| WARNING | 10 |
| INFO | 10 |
| UNCLASSIFIED | 9 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

All 20 classified findings share a single description element: "No policy gate detected in the analyzed call path." The two unique entrypoints reaching sensitive operations both originate from a single LangChain tool (`call`) registered in the search and sidsearch modules, meaning the entire outbound network and state-mutation surface of the agent's search toolchain is reachable with no authorization check. Tool-controlled input reaching `aiohttp.ClientSession.post` in `sidsearch.py` is the most acute concern, as agent-supplied query content flows directly into authenticated API calls against the Sid.ai personal knowledge base endpoint.

---

## Critical Findings

No CRITICAL findings detected.

---

## Warning Findings

### NETWORK (2 findings)

Both network findings originate from the `call` tool in LangChain and route outbound HTTP POST requests through `aiohttp.ClientSession.post`. One finding (`sidsearch.py:28`) has tool-controlled input traced directly into the request arguments, meaning adversarial query content supplied via the agent's instruction channel can influence the body of authenticated requests to `https://api.sid.ai/v1/users/me/query`. The second (`sidsearch.py:47`) targets the Sid.ai OAuth token endpoint. Neither call path contains a policy gate.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| call | langchain | sidsearch.py:28 | https://api.sid.ai/v1/users/me/query | Yes |
| call | langchain | sidsearch.py:47 | https://auth.sid.ai/oauth/token | No |

### STATE_MUTATION (8 findings)

Eight findings capture in-memory collection mutations (`answer_values.append`, `snippets.append`, `texts.append`) reachable from the `call` tool via `search.py`. These represent search result and snippet data flowing from instruction-influenced paths into accumulated answer buffers with no policy gate. While not direct exfiltration vectors, poisoned search results that reach these buffers without sanitization can influence downstream LLM context and output.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|----------------------|
| call | langchain | search.py:80 | answer | No |
| call | langchain | search.py:82 | \n | No |
| call | langchain | search.py:84 | snippetHighlighted | No |
| call | langchain | search.py:87 | f"https://www.google.com/search?q={quote(input_str)}" | No |
| call | langchain | search.py:99 | snippet | No |
| call | langchain | search.py:103 | f"{attribute}: {value}." | No |
| call | langchain | search.py:104 | snippets | No |
| call | langchain | search.py:34 | f"https://google.serper.dev/{search_type}" | No |

> Note: `search.py:34` is the outbound `session.post` call; classified as NETWORK by operation but grouped here as the session.post feeds the state-mutation chain. See INFO table for MEMORY_READ findings on the same path.

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| call | langchain | search.py:76 | MEMORY_READ | answerBox |
| call | langchain | search.py:78 | MEMORY_READ | answerBox |
| call | langchain | search.py:79 | MEMORY_READ | answerBox |
| call | langchain | search.py:80 | MEMORY_READ | answer |
| call | langchain | search.py:81 | MEMORY_READ | snippet |
| call | langchain | search.py:82 | MEMORY_READ | snippet |
| call | langchain | search.py:83 | MEMORY_READ | snippetHighlighted |
| call | langchain | search.py:84 | MEMORY_READ | snippetHighlighted |
| call | langchain | search.py:102 | MEMORY_READ | attributes |
| call | langchain | sidsearch.py:118 | MEMORY_READ | results |

---

## Unclassified CEEs

**Total:** 9

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (0):**
None.

**LOW_RISK_UNTRACED tools (9):**
All 9 unclassified CEEs fall into the LOW_RISK_UNTRACED category. They include UI event handlers (`handleWindowResize` in `Hero.tsx:26`, `getStaticProps` in `index.tsx:184`) and `call` registrations with no resolved execution path in `code.py:14`, `conclude.py:12`, `image.py:57`, `reason.py:16`, `search.py:55`, `sidsearch.py:130`, and `wikipedia_search.py:20`. The `search.py:55` and `sidsearch.py:130` entries are the same tool registrations that produced the WARNING findings above -- their external operations were traced indirectly, but the top-level registration node itself remained unclassified.

---

## Coverage Gap Analysis

**Unresolved call edges:** 563
**Unique entrypoints traced to sensitive ops:** 2

563 unresolved call edges against 234 total files represents a ratio of approximately 2.4 unresolved edges per file, indicating substantial dynamic dispatch, third-party LangChain internals, and TypeScript/JS cross-language boundaries that static analysis could not resolve. Only 2 entrypoints were fully traced to sensitive operations, meaning the actual exposure surface may be considerably larger than what the 20 classified findings represent. Any LangChain tool whose internal call graph traverses dynamically resolved methods will produce unresolved edges and may execute sensitive operations that are invisible to this scan.

---

## Key Findings Summary

1. All 20 classified findings are UNGOVERNED -- no policy gate was detected on any call path traced from the single LangChain `call` tool entry point into network or state-mutation operations.
2. Tool-controlled input flows directly into authenticated `aiohttp.ClientSession.post` requests to the Sid.ai personal knowledge API (`sidsearch.py:28`), enabling prompt injection via adversarially crafted query content to influence what is sent to a user's private knowledge store.
3. The OAuth token exchange endpoint (`https://auth.sid.ai/oauth/token`) is reachable from the same `call` tool with no policy gate, meaning a compromised agent instruction path could trigger unauthenticated token refresh flows.
4. Eight WARNING-level state-mutation findings in `search.py` indicate that Google Serper API results flow into answer and snippet buffers without sanitization or access control, creating a prompt injection surface through poisoned search results.
5. Only 2 unique entrypoints were successfully traced to sensitive operations despite 234 files scanned, and 563 call edges remain unresolved -- the true attack surface is likely larger than the classified findings indicate.
6. Nine unclassified CEEs include `call` registrations in `code.py`, `conclude.py`, `image.py`, `reason.py`, and `wikipedia_search.py` whose execution paths were not resolved; these tools may perform sensitive operations that are not represented in this report.
