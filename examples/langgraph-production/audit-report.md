# Wyscan Security Audit Report

**Auditor**: Independent security assessment
**Date**: 2026-03-24
**Target**: Wyscan v0.6.0
**Test System**: langgraph-production example (multi-agent B2B system)

---

## What Wyscan Claims To Do

According to the README and codebase analysis, Wyscan claims to be a static security analyzer for agentic AI codebases that detects AFB04 (Unauthorized Action) vulnerabilities. It identifies tool registration points (LangChain @tool decorators, BaseTool classes, CrewAI, AutoGen, etc.), builds call graphs to trace execution paths from tools to dangerous operations (shell execution, file deletion, database writes, HTTP mutations), and reports findings where no "policy gate" (authorization check with conditional raise of authorization exceptions) exists in the call path. It classifies findings as CRITICAL (irreversible operations), WARNING (recoverable mutations), and INFO (read operations).

## What Wyscan Actually Does

Based on testing against a realistic production LangGraph agent system, Wyscan successfully parses Python files using tree-sitter, identifies @tool decorated functions, and traces paths to dangerous operations. It correctly identifies most unprotected dangerous operations including subprocess.run, shutil.rmtree, file writes, and HTTP POST/PUT/PATCH calls. However, the scanner has significant gaps: (1) it fails to recognize @require_permission decorator-based authorization gates, producing false positives on protected functions, (2) it misidentifies dict.update() as database write operations, (3) it misses SMTP sendmail operations entirely, and (4) the --level CLI flag does not filter output as documented. The core detection logic works, but authorization gate detection and pattern matching need fixes before production use.

---

## True Positives

These findings are genuine security exposures. A senior security engineer would agree these require attention.

| # | File | Line | Finding | Why It's Real |
|---|------|------|---------|---------------|
| 1 | shell.py | 56 | subprocess.run in run_transformation_command | @tool decorated function directly calls subprocess.run(shell=True). No auth check. Agent can execute arbitrary commands. |
| 2 | shell.py | 125 | file_path.unlink in cleanup_temp_files | @tool decorated function deletes files without authorization. Agent can delete arbitrary files. |
| 3 | shell.py | 131 | shutil.rmtree in cleanup_temp_files | Recursive directory deletion without auth check. High-impact destructive operation. |
| 4 | shell.py | 254 | subprocess.run in run_data_pipeline_script | Shell execution via subprocess.run without authorization. |
| 5 | data_pipeline_agent.py | 74 | requests.post in call_enrichment_api | Sends customer data to external API without authorization check. Data exfiltration risk. |
| 6 | crm.py | 94 | requests.patch in sync_to_crm | Modifies external CRM without auth check. |
| 7 | crm.py | 104 | requests.post in sync_to_crm | Creates records in external CRM without auth check. |
| 8 | crm.py | 171 | requests.post in bulk_sync_to_crm | Bulk data transmission to external system. |
| 9 | files.py | 89 | write_text in write_customer_document | File write operation without authorization. |
| 10 | files.py | 218-219 | open/write in append_to_log | File append operation without auth check. |
| 11 | shell.py | 54 | mkdir in run_transformation_command | Directory creation as part of shell tool. |
| 12 | shell.py | 166 | mkdir in create_processing_workspace | Directory creation without auth. |
| 13 | shell.py | 174 | shutil.copy2 in create_processing_workspace | File copy operation without auth. |
| 14 | tickets.py | 77 | requests.post in create_support_ticket | Creates external ticket without auth. |
| 15 | tickets.py | 134 | requests.put in update_support_ticket | Modifies external ticket without auth. |
| 16 | database.py | 161 | cursor.execute in write_to_database | Database INSERT/UPDATE without auth (classified as INFO, should be WARNING). |

**True Positive Count**: 32 of 38 findings (84%)

---

## False Positives

These findings are wrong. The scanner flagged them incorrectly.

| # | File | Line | Finding | Why It's Wrong |
|---|------|------|---------|----------------|
| 1 | shell.py | 208 | shutil.rmtree in force_cleanup_all_temp | **FALSE POSITIVE**: This function has `@require_permission("admin")` decorator at line 185. The scanner failed to detect this authorization gate. The decorator raises AuthorizationError if the user lacks permission, which should prevent the dangerous operation from being flagged. |
| 2 | shell.py | 209 | temp_path.mkdir in force_cleanup_all_temp | **FALSE POSITIVE**: Same as above - protected by @require_permission("admin"). |
| 3 | data_pipeline_agent.py | 284 | customer.update | **FALSE POSITIVE**: This is `dict.update()` on a local Python dictionary variable, NOT a database write operation. The scanner pattern `/\.update$/i` is too broad and matches Python dict methods. |
| 4 | shell.py | 252 | env.update | **FALSE POSITIVE**: This is `dict.update()` on the environment variable dictionary `env = os.environ.copy(); env.update(env_vars)`. Not a database operation. Same pattern matching issue. |
| 5 | database.py | 193, 198 | cursor.execute in delete_customer_data | **FALSE POSITIVE**: This function has `@require_permission("admin")` decorator at line 171. The scanner should recognize this as a protected operation. |

**False Positive Count**: 6 of 38 findings (16%)

---

## False Negatives

These are real security exposures that the scanner completely missed.

| # | File | Line | Operation | Why It Was Missed |
|---|------|------|-----------|-------------------|
| 1 | email.py | 91 | server.sendmail in send_customer_email | @tool decorated function sends emails to arbitrary addresses via SMTP. This is external data transmission and should be WARNING severity. The scanner doesn't detect smtplib.sendmail as a dangerous operation. |
| 2 | email.py | 147 | server.sendmail in send_bulk_email | Same issue - bulk email transmission not detected. |
| 3 | customer_ops_agent.py | (cross-file) | handle_customer_request calls send_customer_email | Higher-level @tool that orchestrates multiple dangerous operations via cross-file calls. The call graph should trace through to the sendmail inside email.py. |

**False Negative Count**: 3 missed exposures

---

## CLI Audit

| Command | Expected Behavior | Actual Behavior | Status |
|---------|-------------------|-----------------|--------|
| `wyscan scan <path>` | Scan and show all findings | Works correctly. Shows 5 critical, 19 warning, 14 info. | **PASS** |
| `wyscan scan <path> --level critical` | Show only CRITICAL findings | Shows all findings. The count header shows all levels, not filtered to critical only. | **FAIL** |
| `wyscan scan <path> --level warning` | Show CRITICAL + WARNING | Shows all findings including INFO. Filter not working. | **FAIL** |
| `wyscan scan <path> --level info` | Show all findings | Works (shows all). | **PASS** |
| `wyscan scan <path> --json` | JSON output format | Works correctly. Valid JSON with proper schema. | **PASS** |
| `wyscan scan <path> --summary` | One-line summary only | Works correctly. Shows "5 critical  ·  19 warning  ·  14 info  ·  12 files" | **PASS** |
| `wyscan scan <path> --output <file>` | Write to file | Works correctly. File created with full output. | **PASS** |
| `wyscan scan <path> --quiet` | No output, exit code only | Works correctly. Silent, returns exit code 2 for critical findings. | **PASS** |
| `wyscan check` | Verify dependencies | Works correctly. Shows Node.js, parser status. | **PASS** |
| `wyscan version` | Show version | Works. Shows "argus 0.6.0". | **PASS** |
| `wyscan help` | Show help text | Works. Shows complete usage information. | **PASS** |

**CLI Issues**:
1. The `--level` flag does not filter output as documented
2. Brand name inconsistency: CLI shows "argus" but project is "wyscan"

---

## Verdict

**NEEDS FIXES**

The core detection logic works and produces mostly genuine findings. The scanner successfully identifies tool registration points, builds call graphs, and traces to dangerous operations. However, there are specific issues that must be fixed before production use:

1. Authorization gate detection fails for decorator-based patterns like `@require_permission`
2. Pattern matching produces false positives on dict.update()
3. SMTP sendmail is not detected as a dangerous operation
4. The --level CLI flag does not filter output

These are fixable with targeted changes, not fundamental architectural problems.

---

## What To Fix

### Fix 1: Recognize @require_permission decorator as authorization gate

**Problem**: Functions decorated with `@require_permission("admin")` are still flagged because the scanner doesn't recognize this as a valid authorization gate.

**Location**: `src/analyzer/python/call-graph.ts` - `isStructuralPolicyGate()` function

**Solution**: Add decorator-based gate detection. When analyzing a function, check if any decorators match authorization patterns like `require_permission`, `require_admin`, `login_required`, `permission_required`. If found, treat the function as having a gate.

### Fix 2: Exclude dict.update() from database write patterns

**Problem**: The pattern `/\.update$/i` matches Python `dict.update()` which is not a database operation.

**Location**: `src/analyzer/python/call-graph.ts` - `DANGEROUS_OPERATION_PATTERNS`

**Solution**: Make the pattern more specific. Change from `/\.update$/i` to require database context like `/\.session\.update$/i` or `/cursor\.update$/i`. Alternatively, exclude when the receiver is a dict literal or variable.

### Fix 3: Add SMTP sendmail to dangerous operation patterns

**Problem**: `smtplib.SMTP.sendmail()` is not detected as dangerous, but it transmits data externally.

**Location**: `src/analyzer/python/call-graph.ts` - `DANGEROUS_OPERATION_PATTERNS`

**Solution**: Add pattern for SMTP operations:
```typescript
{ pattern: /\.sendmail$/i, severity: 'WARNING', category: 'email', description: 'Email transmission to external SMTP server' }
```

### Fix 4: Fix --level flag filtering

**Problem**: The --level flag does not filter findings in the output.

**Location**: `src/cli/index.ts` or `src/cli/formatter.ts`

**Solution**: Apply level filter to findings before display. If `--level critical`, only show findings where severity === 'CRITICAL'. If `--level warning`, show CRITICAL and WARNING.

---

## Summary Statistics

| Metric | Count | Status |
|--------|-------|--------|
| CRITICAL findings | 5 | 4 true, 1 false positive |
| WARNING findings | 19 | 16 true, 3 false positives |
| INFO findings | 14 | 12 true, 2 false positives |
| **Total findings** | 38 | |
| **True positives** | 32 | 84% |
| **False positives** | 6 | 16% |
| **False negatives** | 3 | |
| **CLI commands** | 11 tested | 9 pass, 2 fail |

The scanner is fundamentally sound but requires the four fixes listed above before it can be confidently used in production security workflows.
