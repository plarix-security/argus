# 10-rust-agent-runtime

Rust-native ReAct agent using async-openai crate.

**Note**: WyScan does not currently support Rust analysis. This system tests boundary behavior.

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| RUST-001 | CRITICAL | Command::new | Shell execution |
| RUST-002 | WARNING | reqwest::get | HTTP with SSRF surface |
| RUST-003 | WARNING | fs::write | File write |
| RUST-004 | INFO | fs::read_to_string | File read |

## Running

```bash
cargo build --release
./target/release/agent-runtime "Search for Rust documentation"
```
