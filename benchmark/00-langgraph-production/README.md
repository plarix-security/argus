# Customer Operations Platform - LangGraph Production System

A realistic multi-agent AI system built with LangGraph for enterprise B2B SaaS operations. This system demonstrates production-grade patterns including cross-agent coordination, shared state management, and integration with external services.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      ORCHESTRATOR                                │
│                   (LangGraph StateGraph)                         │
│                                                                  │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────┐  │
│  │   Classify   │───▶│  Route Task   │───▶│     Handoff      │  │
│  │    Node      │    │  (Conditional)│    │      Node        │  │
│  └──────────────┘    └───────────────┘    └──────────────────┘  │
│         │                   │                      │             │
│         ▼                   ▼                      │             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     SHARED STATE                          │   │
│  │  - messages, customer_id, job_context, completed_steps   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                                     ▼
┌─────────────────────────┐         ┌─────────────────────────┐
│  CUSTOMER OPS AGENT     │         │   DATA PIPELINE AGENT   │
│                         │         │                         │
│  Tools:                 │         │  Tools:                 │
│  • query_customer_db    │         │  • execute_sql_query    │
│  • send_customer_email  │         │  • read_csv_file        │
│  • create_support_ticket│         │  • write_to_database    │
│  • update_support_ticket│         │  • call_enrichment_api  │
│  • read_customer_doc    │         │  • run_transformation   │
│  • write_customer_doc   │         │  • cleanup_temp_files   │
│  • sync_to_crm          │         │  • run_etl_pipeline     │
│  • get_customer_context │         │  • process_data_batch   │
│  • handle_customer_req  │         │  • enrich_and_store     │
└─────────────────────────┘         └─────────────────────────┘
           │                                     │
           └──────────────────┬──────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SHARED TOOLS                               │
│                                                                  │
│  tools/auth.py     - Authorization utilities & decorators        │
│  tools/database.py - PostgreSQL operations                       │
│  tools/email.py    - SMTP email sending                          │
│  tools/tickets.py  - REST API ticket management                  │
│  tools/files.py    - File read/write operations                  │
│  tools/crm.py      - External CRM API integration                │
│  tools/shell.py    - Shell command execution                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
langgraph-production/
├── README.md                 # This file
├── config.py                 # Centralized configuration
├── orchestrator.py           # Main LangGraph StateGraph
├── agents/
│   ├── customer_ops_agent.py # Customer Operations Agent
│   └── data_pipeline_agent.py# Data Pipeline Agent
└── tools/
    ├── __init__.py           # Tool exports
    ├── auth.py               # Authorization utilities
    ├── database.py           # PostgreSQL operations
    ├── email.py              # SMTP email operations
    ├── tickets.py            # Ticketing API operations
    ├── files.py              # File system operations
    ├── crm.py                # CRM API integration
    └── shell.py              # Shell command execution
```

## Agents

### Customer Operations Agent

Handles customer-facing operations:
- **Database queries**: Customer lookups and data retrieval
- **Email communications**: Customer notifications and bulk emails
- **Support tickets**: Create, update, and query support tickets
- **Document management**: Read and write customer documents
- **CRM synchronization**: Sync customer data to external CRM

### Data Pipeline Agent

Handles data processing workflows:
- **SQL execution**: Run queries with user-supplied parameters
- **CSV processing**: Read and parse CSV input files
- **Database writes**: Insert and update processed data
- **Data enrichment**: Call external APIs to enrich customer data
- **Shell commands**: Execute transformation scripts
- **ETL pipelines**: Orchestrate complete extract-transform-load workflows

## Security Model

### Tools WITH Authorization Checks

These tools have proper authorization gates and should NOT be flagged by security scanners:

- `delete_customer_data()` - Requires `@require_permission("admin")`
- `force_cleanup_all_temp()` - Requires `@require_permission("admin")`

### Tools WITHOUT Authorization Checks

These represent realistic production code where authorization is often deferred or missing:

- `query_customer_db()` - Database read (low risk)
- `execute_sql_query()` - Arbitrary SQL execution (medium risk)
- `write_to_database()` - Database writes (medium risk)
- `send_customer_email()` - Email transmission (medium risk)
- `create_support_ticket()` - External API mutation (medium risk)
- `update_support_ticket()` - External API mutation (medium risk)
- `sync_to_crm()` - External API mutation (medium risk)
- `call_enrichment_api()` - Data exfiltration potential (medium risk)
- `read_customer_document()` - File system read (low risk)
- `write_customer_document()` - File system write (medium risk)
- `read_csv_file()` - File system read (low risk)
- `run_transformation_command()` - Shell execution (HIGH risk)
- `cleanup_temp_files()` - File deletion (HIGH risk)
- `run_data_pipeline_script()` - Shell execution (HIGH risk)

## Configuration

Configuration is managed through environment variables. See `config.py` for all available settings:

```bash
# Database
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=customer_ops
export POSTGRES_USER=app_user
export POSTGRES_PASSWORD=secret

# Email
export SMTP_HOST=smtp.company.com
export SMTP_PORT=587
export SMTP_USER=support@company.com
export SMTP_PASSWORD=secret

# APIs
export TICKETING_API_URL=https://tickets.company.com/api/v1
export TICKETING_API_KEY=tk_xxx
export CRM_API_URL=https://api.salesforce.com/v52.0
export CRM_ACCESS_TOKEN=sf_xxx
export ENRICHMENT_API_URL=https://api.clearbit.com/v2
export ENRICHMENT_API_KEY=sk_xxx

# Files
export DOCUMENTS_DIR=/var/data/documents
export CSV_INPUT_DIR=/var/data/csv_input
export TEMP_DIR=/tmp/customer_ops
```

## Usage

```python
from orchestrator import run_orchestrator

# Customer operations workflow
result = run_orchestrator(
    "Create a support ticket for customer CUST-123 about their billing issue",
    customer_id="CUST-123"
)

# Data pipeline workflow
result = run_orchestrator(
    "Process the customer export CSV and load it into the analytics database"
)

# Cross-agent workflow
result = run_orchestrator(
    "Look up customer CUST-456, enrich their data, and send them an onboarding email"
)
```

## Testing

This fixture is part of the current Python benchmark suite.

Current benchmark validation for this fixture is recorded in `../BENCHMARK_RESULTS.md`.

## License

Internal use only. Part of the Wyscan security scanner test suite.
