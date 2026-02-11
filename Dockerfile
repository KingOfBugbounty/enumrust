# ============================================================
# EnumRust v2.3.0 - Multi-stage Docker Build
# All 19 external security tools pre-installed
# ============================================================

# Stage 1: Build Rust binaries
FROM rust:bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY dashboard-ui/ dashboard-ui/

# Build release binaries
RUN cargo build --release --bin enumrust --bin regen_report

# Install feroxbuster (Rust-based, build in builder stage)
RUN cargo install feroxbuster

# ============================================================
# Stage 2: Runtime with all security tools
# ============================================================
FROM debian:bookworm-slim AS runtime

LABEL maintainer="OFJAAAH <ofjaaah@users.noreply.github.com>"
LABEL description="EnumRust - Advanced Security Reconnaissance Tool"
LABEL version="2.3.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# Install system dependencies + apt-based tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    masscan \
    jq \
    whois \
    tmux \
    wget \
    curl \
    libssl3 \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go + all Go-based security tools + cleanup in single layer
RUN wget -q https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz \
    # Core tools
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    # Discovery tools
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/hakluke/haktrails@latest \
    && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    # Fuzzing
    && go install -v github.com/ffuf/ffuf/v2@latest \
    # Utils
    && go install -v github.com/tomnomnom/anew@latest \
    # Crawling tools
    && go install -v github.com/hakluke/hakrawler@latest \
    && go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    # Trufflehog (requires clone+build due to replace directives in go.mod)
    && git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog \
    && cd /tmp/trufflehog \
    && go build -o /root/go/bin/trufflehog . \
    && rm -rf /tmp/trufflehog \
    # Update nuclei templates
    && nuclei -ut || true \
    # Clean up Go SDK, build cache, module cache, and gcc (only needed for katana CGO)
    && rm -rf /usr/local/go /root/go/pkg /root/go/src \
    && rm -rf /root/.cache/go-build \
    && apt-get purge -y gcc libc6-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /build/target/release/enumrust /usr/local/bin/enumrust
COPY --from=builder /build/target/release/regen_report /usr/local/bin/regen_report
COPY --from=builder /usr/local/cargo/bin/feroxbuster /usr/local/bin/feroxbuster

# Copy wordlist
COPY src/words_and_files_top5000.txt /opt/enumrust/words_and_files_top5000.txt

# Copy dashboard UI
COPY dashboard-ui/ /opt/enumrust/dashboard-ui/

WORKDIR /results

# Dashboard port
EXPOSE 8080

ENTRYPOINT ["enumrust"]
