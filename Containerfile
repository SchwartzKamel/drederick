# Drederick - Slim & fast offensive harness (Podman/Docker)
# Multi-stage: build drederick, then minimal runtime
# Build: docker build -t drederick:latest . OR podman build -t drederick:latest .
# Run:   docker run --rm -v "$PWD/scope.yaml:/scope.yaml" -v "$PWD/out:/out" drederick --scope /scope.yaml --target 127.0.0.1 --out /out

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  curl ca-certificates && \
  cd /tmp && \
  curl -fsSL -O https://github.com/SchwartzKamel/drederick/releases/download/v0.3.1/drederick-0.3.1-linux-x64.tar.gz && \
  tar xzf drederick-0.3.1-linux-x64.tar.gz && \
  chmod +x drederick

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="drederick"
LABEL org.opencontainers.image.description="Full-auto offensive security harness"
LABEL org.opencontainers.image.source="https://github.com/SchwartzKamel/drederick"
LABEL org.opencontainers.image.version="0.3.1"

# Minimal offensive toolchain: recon + basic enum only
RUN apt-get update && apt-get install -y --no-install-recommends \
  nmap \
  python3 python3-pip \
  git curl jq ca-certificates \
  dumb-init \
  && python3 -m pip install --no-cache-dir --quiet impacket netexec 2>/dev/null || true \
  && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy drederick from builder
COPY --from=builder /tmp/drederick /usr/local/bin/drederick

# Setup
RUN mkdir -p /out && chmod 777 /out

WORKDIR /work

ENTRYPOINT ["drederick"]
CMD ["doctor"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=2 \
  CMD drederick doctor > /dev/null 2>&1 || exit 1

