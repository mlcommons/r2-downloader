FROM ubuntu:latest

ARG TARGETARCH

# Install dependencies, download architecture-specific cloudflared, and clean up in one layer
RUN set -euo pipefail; \
    arch="$TARGETARCH"; \
    case "$arch" in \
      amd64|arm64) ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    apt update && apt install -y \
      bash \
      curl \
      wget \
      coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && wget -O /usr/local/bin/cloudflared \
       "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch" \
    && chmod +x /usr/local/bin/cloudflared \
    && cloudflared --version

# Add r2-downloader
COPY mlc-r2-downloader.sh /usr/local/bin/r2-downloader
RUN chmod +x /usr/local/bin/r2-downloader

# Set working directory where files will be downloaded
WORKDIR /download
