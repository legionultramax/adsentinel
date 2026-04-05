# ADSentinel - Multi-stage Dockerfile
# Build: docker build -t adsentinel .
# Run:   docker run --rm -it --env-file .env adsentinel scan --server dc01 --domain corp.com

# ---- Build stage ----
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir build setuptools wheel

# Copy only what's needed for install
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build wheel
RUN python -m build --wheel --outdir /build/dist

# ---- Runtime stage ----
FROM python:3.11-slim AS runtime

LABEL maintainer="legionultramax <harsh@adsentinel.dev>"
LABEL description="ADSentinel - Elite Active Directory Security Assessment Tool"
LABEL org.opencontainers.image.source="https://github.com/legionultramax/adsentinel"

# Install runtime OS deps (for Kerberos support)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libkrb5-dev \
        dnsutils \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r adsentinel && useradd -r -g adsentinel -m adsentinel

WORKDIR /app

# Install the wheel from build stage + optional extras
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    pip install --no-cache-dir "adsentinel[kerberos]" 2>/dev/null || true && \
    rm -f /tmp/*.whl

# Create output directory
RUN mkdir -p /app/reports && chown adsentinel:adsentinel /app/reports

# Copy default config
COPY config/ /app/config/

# Switch to non-root user
USER adsentinel

# Default output directory
VOLUME ["/app/reports"]

# Healthcheck - verify the tool is installed
HEALTHCHECK --interval=30s --timeout=5s CMD adsentinel version || exit 1

ENTRYPOINT ["adsentinel"]
CMD ["--help"]
