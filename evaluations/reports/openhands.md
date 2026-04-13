# Wyscan Security Report: OpenHands

> **Scan date:** 2026-04-12
> **Wyscan version:** v1.6.2 | Plarix | AFB04 Taxonomy v1.6
> **Repo:** https://github.com/All-Hands-AI/OpenHands
> **Framework(s) detected:** pydantic-ai

## About This System

OpenHands (formerly OpenDevin) is an open-source AI software development agent that operates a full computer environment: it can run shell commands, edit files, browse the web, and execute code in a sandboxed runtime. Selected for evaluation because it represents the broadest possible agent capability surface -- effectively a general-purpose computer-use agent -- making authorization gaps especially consequential, as unrestricted operation execution could lead to arbitrary code execution, file system compromise, or exfiltration.

---

## Scan Summary

| Metric | Value |
|--------|-------|
| Files scanned | 1702 |
| Scan duration | 42.5s |
| Total CEEs detected | 80 |
| Classified findings | 15 |
| Unclassified CEEs | 65 |
| Unique entrypoints reaching sensitive ops | 65 |
| Unresolved call edges (coverage gap) | 4849 |

**Severity breakdown:**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| WARNING | 5 |
| INFO | 10 |
| UNCLASSIFIED | 65 |

---

## AFB04 Authorization Gap Assessment

**Governance status: UNGOVERNED** (100% of classified findings have no policy gate detected)

All 15 classified findings across WARNING and INFO severity report no policy gate in the analyzed call path. The 5 WARNING findings share a single code site -- `conversation.pr_number.append(pr_number)` in `mcp.py:84` -- reached from five distinct VCS integration tools (GitHub, GitLab, Bitbucket, Bitbucket Data Center, Azure DevOps), indicating a systemic missing authorization check on pull/merge request creation. The 10 INFO findings expose credential retrieval operations (provider tokens and conversation session IDs) reachable from the same five tools with no gate.

---

## Critical Findings

No CRITICAL findings detected.

---

## Warning Findings

### STATE_MUTATION (5 findings)

Five VCS integration tools -- covering GitHub, GitLab, Bitbucket, Bitbucket Data Center, and Azure DevOps -- all reach the same `conversation.pr_number.append(pr_number)` call at `mcp.py:84` through a single intermediate call. No policy gate is present in any path. This means any agent instruction invoking these tools can append arbitrary PR/MR numbers to the conversation state without authorization, potentially corrupting session tracking or enabling confused-deputy attacks across VCS providers.

| Tool | Framework | File:Line | Resource Hint | Tool-Controlled Input |
|------|-----------|-----------|---------------|-----------------------|
| create_pr | pydantic-ai | `mcp.py:84` | `pr_number` | No |
| create_mr | pydantic-ai | `mcp.py:84` | `pr_number` | No |
| create_bitbucket_pr | pydantic-ai | `mcp.py:84` | `pr_number` | No |
| create_bitbucket_data_center_pr | pydantic-ai | `mcp.py:84` | `pr_number` | No |
| create_azure_devops_pr | pydantic-ai | `mcp.py:84` | `pr_number` | No |

---

## Info Findings

| Tool | Framework | File:Line | Operation | Resource Hint |
|------|-----------|-----------|-----------|---------------|
| create_pr | pydantic-ai | `mcp.py:115` | IDENTITY | `X-OpenHands-ServerConversation-ID` |
| create_pr | pydantic-ai | `mcp.py:122` | IDENTITY | `ProviderType.GITHUB` |
| create_mr | pydantic-ai | `mcp.py:188` | IDENTITY | `X-OpenHands-ServerConversation-ID` |
| create_mr | pydantic-ai | `mcp.py:195` | IDENTITY | `ProviderType.GITLAB` |
| create_bitbucket_pr | pydantic-ai | `mcp.py:255` | IDENTITY | `X-OpenHands-ServerConversation-ID` |
| create_bitbucket_pr | pydantic-ai | `mcp.py:262` | IDENTITY | `ProviderType.BITBUCKET` |
| create_bitbucket_data_center_pr | pydantic-ai | `mcp.py:322` | IDENTITY | `X-OpenHands-ServerConversation-ID` |
| create_bitbucket_data_center_pr | pydantic-ai | `mcp.py:329` | IDENTITY | `ProviderType.BITBUCKET_DATA_CENTER` |
| create_azure_devops_pr | pydantic-ai | `mcp.py:389` | IDENTITY | `X-OpenHands-ServerConversation-ID` |
| create_azure_devops_pr | pydantic-ai | `mcp.py:396` | IDENTITY | `ProviderType.AZURE_DEVOPS` |

---

## Unclassified CEEs

**Total:** 65

Unclassified CEEs are tool registrations where no external operations were traced from the entry point. This does not mean they are safe -- it means the call graph did not resolve their execution path.

**HIGH_RISK_UNTRACED tools (0):**
None.

**MEDIUM_RISK_UNTRACED tools (0):**
None.

**LOW_RISK_UNTRACED tools (65):**
All 65 unclassified CEEs are TypeScript/JavaScript frontend UI components, event handlers, hooks, test utilities, and type guards -- none matching HIGH or MEDIUM risk function name patterns. Examples include `handleKeyDown`, `ChatInputActions`, `ConversationPanel`, `handleScroll`, `useHandleWSEvents`, `isExecuteBashActionEvent`, `handleVisibilityChange`, `generateAssistantMessageAction`, `createMockExecuteBashActionEvent`, `handleStorage`, `mutateWithToast`, `EventHandler`, `Dialog`, `Tooltip`, `activate` (VSCode extension stubs). These represent browser-side event infrastructure with no traceable external operation paths in the call graph.

---

## Coverage Gap Analysis

**Unresolved call edges:** 4849
**Unique entrypoints traced to sensitive ops:** 65

The 4849 unresolved call edges represent a significant static analysis blind spot, particularly given OpenHands' TypeScript/JS frontend (863 files analyzed) and its Python backend. The call graph was built across 1702 files but could not resolve nearly 5000 edges -- likely due to dynamic dispatch, runtime module loading, and cross-language boundaries between the TypeScript frontend and Python agent runtime. All 65 unique entrypoints that did reach sensitive operations are the VCS MCP tools in `mcp.py`; the agent's core execution capabilities (shell commands, file edits, browser operations) operate through a separate runtime path not fully resolved in this scan.

---

## Key Findings Summary

1. No CRITICAL findings were detected in the classified set; however, the 4849 unresolved call edges mean OpenHands' primary capability surface -- shell execution, file system access, and browser control -- was not fully traced and may harbor ungoverned paths not captured here.
2. All 5 WARNING findings share a single vulnerable code site (`mcp.py:84`, `conversation.pr_number.append`) reached from five independent VCS tools, indicating a structural missing authorization check rather than isolated tool-specific gaps.
3. All 10 INFO findings expose provider credential retrieval (`provider_tokens.get`) and session ID access (`headers.get('X-OpenHands-ServerConversation-ID')`) reachable from the same five VCS tools with no policy gate, enabling credential-adjacent operations without authorization.
4. The 65 unclassified CEEs are entirely frontend UI code (TypeScript event handlers, hooks, type guards), yielding zero HIGH or MEDIUM risk untraced tools in the classified set -- but this reflects the scope of static tracing, not the absence of risk in the agent runtime.
5. 100% of classified findings (15/15) have no policy gate detected, confirming the MCP server layer in OpenHands has no implemented authorization controls in the analyzed paths.
