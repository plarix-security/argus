# WyScan Benchmark Results

**Run Date:** 2026-03-31
**Benchmarks Evaluated:** 13
**Python Exact-Match Cases:** 8/8 passed
**Python CEE-Validated Cases:** 1/1 passed
**Asset-Limited Cases:** 4

## Summary

| System | Languages | Expected result | Actual result | Status | Notes |
|--------|-----------|-----------------|---------------|--------|-------|
| 00-langgraph-production | python | Operational Python scan with no failed files plus CEE validation | 79 cees, 75 afb04 findings (8C/41W/26I), exit 2, analyzed 12, skipped 0, failed 0 | PASS | CEE validation passed with 79 inventoried events |
| 01-react-tool-agent | python | Exact match with 7 expected Python findings | 8 cees, 7 afb04 findings (2C/3W/2I), exit 2, analyzed 8, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 8 CEEs were inventoried. |
| 02-langchain-rag-agent | python | Exact match with 6 expected Python findings | 6 cees, 6 afb04 findings (1C/4W/1I), exit 2, analyzed 6, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 6 CEEs were inventoried. |
| 03-langgraph-supervisor | python | Exact match with 11 expected Python findings | 11 cees, 11 afb04 findings (2C/6W/3I), exit 2, analyzed 8, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 11 CEEs were inventoried. |
| 04-crewai-research-crew | python | Exact match with 11 expected Python findings | 11 cees, 11 afb04 findings (1C/9W/1I), exit 2, analyzed 9, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 11 CEEs were inventoried. |
| 05-openai-assistants-parallel | typescript | No analyzable source files in current snapshot | 0 cees, 0 afb04 findings (0C/0W/0I), exit 0, analyzed 0, skipped 0, failed 0 | PASS | This repo snapshot contains no analyzable source files for this fixture. The result does not validate skipped-language handling. |
| 06-autogen-code-executor | python | Exact match with 5 expected Python findings | 5 cees, 5 afb04 findings (2C/2W/1I), exit 2, analyzed 1, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 5 CEEs were inventoried. |
| 07-langgraph-memory-agent | python | Exact match with 5 expected Python findings | 5 cees, 5 afb04 findings (0C/3W/2I), exit 1, analyzed 5, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 5 CEEs were inventoried. |
| 08-typescript-browser-agent | typescript | No analyzable source files in current snapshot | 0 cees, 0 afb04 findings (0C/0W/0I), exit 0, analyzed 0, skipped 0, failed 0 | PASS | This repo snapshot contains no analyzable source files for this fixture. The result does not validate skipped-language handling. |
| 09-multi-agent-pipeline-fastapi | python | Exact match with 7 expected Python findings | 7 cees, 7 afb04 findings (2C/2W/3I), exit 2, analyzed 7, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 7 CEEs were inventoried. |
| 10-rust-agent-runtime | rust | No analyzable source files in current snapshot | 0 cees, 0 afb04 findings (0C/0W/0I), exit 0, analyzed 0, skipped 0, failed 0 | PASS | This repo snapshot contains no analyzable source files for this fixture. The result does not validate skipped-language handling. |
| 11-smolagents-computer-use | python | Exact match with 5 expected Python findings | 5 cees, 5 afb04 findings (2C/2W/1I), exit 2, analyzed 6, skipped 0, failed 0 | PASS | Python manifest count matched exactly. 5 CEEs were inventoried. |
| 12-heterogeneous-multi-framework | python, typescript | No analyzable source files in current snapshot | 0 cees, 0 afb04 findings (0C/0W/0I), exit 0, analyzed 0, skipped 0, failed 0 | PASS | This repo snapshot contains no analyzable source files for this fixture. The result does not validate skipped-language handling. |

## Interpretation

- PASS on an exact-match Python case means the current scanner found the same number of findings as the benchmark manifest and reported no failed files.
- PASS on a CEE-validated Python case means the current scanner also satisfied the manifest's required CEE identities or minimum CEE coverage.
- PASS on an asset-limited case means the repository snapshot contained no analyzable source files and the scanner reported no findings and no failed files.
- These results validate the current Python-first scanner. They do not claim TypeScript, JavaScript, or Rust finding support.
