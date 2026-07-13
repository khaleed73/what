# =============================================================================
# rust-hft-arb — Multi-stage production Dockerfile
# =============================================================================
# Build:  docker build -t rust-hft-arb .
# Run:    docker run --rm -v ./config.toml:/app/config.toml rust-hft-arb
# =============================================================================

# --- Stage 1: Build ---
FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for dependency caching.
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies.
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Copy actual source and rebuild.
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false hft

WORKDIR /app

# Copy the release binary.
COPY --from=builder /build/target/release/rust-hft-arb /app/rust-hft-arb

# Copy default config template (optional — real config mounted at runtime).
COPY config.toml /app/config.toml.example

# Non-root runtime.
USER hft

# Expose Prometheus metrics port.
EXPOSE 9090

# Health check: metrics endpoint must respond.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/usr/bin/curl", "-sf", "http://localhost:9090/metrics"]

ENTRYPOINT ["/app/rust-hft-arb"]