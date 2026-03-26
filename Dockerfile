FROM oven/bun:1 AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip3 install --break-system-packages semgrep

# Install Trivy (direct binary download)
ARG TRIVY_VERSION=0.69.3
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then T_ARCH="ARM64"; elif [ "$ARCH" = "amd64" ]; then T_ARCH="64bit"; else T_ARCH="$ARCH"; fi && \
    curl -sSfL -k "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T_ARCH}.deb" \
    -o /tmp/trivy.deb && \
    dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb

# Install Gitleaks (direct binary download)
ARG GITLEAKS_VERSION=8.30.1
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then GL_ARCH="x64"; else GL_ARCH="$ARCH"; fi && \
    curl -sSfL -k "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks

# Set up app
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY src/ ./src/
COPY tsconfig.json ./

# Verify scanners installed
RUN semgrep --version && trivy --version && gitleaks version

ENV MIMIR_TARGET_DIR=/workspace
ENV MIMIR_SCANNERS=semgrep,trivy,gitleaks
ENV MIMIR_MIN_SEVERITY=low

# Download trivy DB ahead of time so scans are faster
RUN trivy fs --download-db-only 2>/dev/null || true

ENTRYPOINT ["bun", "run", "src/index.ts"]
