# Intentionally vulnerable Dockerfile for testing Trivy scanning
# DO NOT use this in production

# Bad: Using 'latest' tag - no version pinning
FROM ubuntu:latest

# Bad: Running as root (no USER directive to switch)
# Bad: Hardcoded secrets in environment variables
ENV API_KEY=sk-1234567890abcdef
ENV DB_PASSWORD=admin123
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Bad: No version pinning for packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Bad: Exposing SSH port
EXPOSE 22

# Bad: Exposing all ports
EXPOSE 0-65535

# Bad: Using ADD instead of COPY (ADD can fetch remote URLs)
ADD https://example.com/app.tar.gz /app/

# Bad: Downloading and executing scripts
RUN curl -sSL https://example.com/install.sh | bash

# Bad: COPY with broad permissions
COPY --chmod=777 . /app/

# Bad: Running as root with no privilege drop
WORKDIR /app
CMD ["./start.sh"]
