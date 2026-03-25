# WyScan

Static analyzer for agentic AI codebases that detects unsafe tool boundaries.

WyScan scans Python agent code and finds places where LLM-callable tools can reach dangerous operations without authorization checks.

## What It Does

- Identifies tool registrations (LangChain, CrewAI, AutoGen, LlamaIndex, MCP, OpenAI)
- Builds a call graph from tool definitions
- Traces paths to dangerous operations (shell execution, file deletion, HTTP mutations)
- Reports paths that lack policy gates

## Quick Example

```bash
wyscan scan ./my-agent-project
```

```
CRITICAL  tools/setup.py:60
shutil.rmtree(agent_dir) reachable from @tool (langchain)
No policy gate in call path. Agent can delete directories.

1 critical  1 warning  3 info  12 files  0.4s
```

## Documentation

- [Installation](install.md)
- [Usage](usage.md)
- [What It Detects](detection.md)
- [GitHub App Setup](github-app.md)
- [Limitations](limitations.md)

## Links

- [GitHub Repository](https://github.com/plarix-security/wyscan)
- [Report Issues](https://github.com/plarix-security/wyscan/issues)
