# 03-langgraph-supervisor

Supervisor/worker multi-agent system using LangGraph 0.2+ with researcher, coder, and critic agents.

## Architecture

```
                    ┌─────────────────┐
                    │   Supervisor    │
                    │    (Router)     │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          v                  v                  v
    ┌───────────┐     ┌───────────┐     ┌───────────┐
    │Researcher │     │   Coder   │     │  Critic   │
    │  Agent    │     │   Agent   │     │  Agent    │
    └─────┬─────┘     └─────┬─────┘     └─────┬─────┘
          │                 │                 │
          v                 v                 v
    Web Search ⚠️    Shell Exec ⚠️      Review &
                    + exec() ⚠️       Route Back
```

## Intentional Vulnerabilities

### CRITICAL: Shell Execution (AFB04)
- **File**: `src/agents/coder_agent.py:42`
- **Pattern**: `subprocess.run(code, shell=True)`
- **Attack**: LLM generates malicious shell commands

### CRITICAL: exec() Code Execution (AFB04)
- **File**: `src/agents/coder_agent.py:58`
- **Pattern**: `exec(generated_code)` as fallback
- **Attack**: Python code runs in host process memory

### WARNING: Shared State Mutation (AFB03)
- **File**: `src/tools/shared_state.py:28`
- **Pattern**: All agents can write to shared state file
- **Attack**: One agent poisons state to influence others

## Running

```bash
cp .env.example .env
pip install -r requirements.txt
python -m src.main "Research and implement a fibonacci function"
```

## Expected WyScan Findings

| ID | Severity | Operation | Agent/Tool |
|----|----------|-----------|------------|
| SUPER-001 | CRITICAL | subprocess.run | execute_code |
| SUPER-002 | CRITICAL | exec | execute_python |
| SUPER-003 | WARNING | requests.get | web_research |
| SUPER-004 | WARNING | write_text | save_code |
| SUPER-005 | WARNING | write_text | update_shared_state |
| SUPER-006 | INFO | read_text | read_code |
| SUPER-007 | INFO | read_text | get_shared_state |
