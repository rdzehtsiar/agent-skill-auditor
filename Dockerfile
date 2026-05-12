# SPDX-License-Identifier: Apache-2.0

FROM rust:1-bookworm AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p agent-audit-cli --bin agent-audit

FROM debian:bookworm-slim AS runtime

COPY --from=builder /workspace/target/release/agent-audit /usr/local/bin/agent-audit

WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/agent-audit"]
CMD ["scan", "/workspace"]
