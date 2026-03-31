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

## Validation Note

Current benchmark validation for this fixture is recorded in `../BENCHMARK_RESULTS.md`.

The scenario description above is the fixture design. It is not a stable scanner-output contract by itself.
