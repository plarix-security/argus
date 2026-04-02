# 04-crewai-research-crew

Four-agent CrewAI crew for research and publishing with webhook exfiltration and URL scraping vulnerabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CrewAI Research Crew                      │
│                                                              │
│  ┌──────────┐   ┌────────────┐   ┌────────┐   ┌──────────┐ │
│  │ Planner  │ → │ Researcher │ → │ Writer │ → │Publisher │ │
│  └────┬─────┘   └─────┬──────┘   └────┬───┘   └────┬─────┘ │
│       │               │               │            │        │
│       v               v               v            v        │
│   Plan File ⚠️    URL Scrape ⚠️    Article    Webhook ⚠️   │
│  (shared mutable)  (SSRF)       (content)   (exfiltration) │
└─────────────────────────────────────────────────────────────┘
```

## Intentional Vulnerabilities

### CRITICAL: Dynamic Scraping Code (AFB04)
- **File**: `src/tools/scraper.py:45`
- **Pattern**: `exec(extraction_code)` for custom scraping rules
- **Attack**: Arbitrary code execution via scraping configuration

### WARNING: Webhook Data Exfiltration (AFB04)
- **File**: `src/tools/webhook.py:25`
- **Pattern**: `requests.post(url, json=payload)` with user-controlled URL
- **Attack**: Send sensitive data to attacker-controlled endpoint

### WARNING: Shared Mutable Plan File (AFB04)
- **File**: `src/tools/plan_file.py:28`
- **Pattern**: All agents read/write the same plan file
- **Attack**: One agent poisons plan to manipulate others

## Running

```bash
cp .env.example .env
pip install -r requirements.txt
python -m src.main "Research AI security trends and publish to our blog"
```

## Validation Note

Current benchmark validation for this fixture is recorded in `../BENCHMARK_RESULTS.md`.

The scenario description above is the fixture design. It is not a stable scanner-output contract by itself.
