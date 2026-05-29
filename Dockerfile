FROM rust:1-alpine AS chef
RUN apk add --no-cache musl-dev && cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM alpine:latest
LABEL org.opencontainers.image.description="Secure IMAP MCP server over stdio with cursor-based pagination, multi-account support, and TLS-only connections"
COPY --from=builder /app/target/release/mail-mcp /mail-mcp
ENTRYPOINT ["/mail-mcp"]
