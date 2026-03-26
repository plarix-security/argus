FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/agent-runtime /usr/local/bin/
ENTRYPOINT ["agent-runtime"]
