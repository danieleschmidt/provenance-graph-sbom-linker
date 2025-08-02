# Development container for Provenance Graph SBOM Linker
FROM mcr.microsoft.com/devcontainers/go:1.21-bullseye

# Install additional tools
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        curl \
        wget \
        git \
        make \
        jq \
        yq \
        tree \
        htop \
        vim \
        nano \
        postgresql-client \
        sqlite3 \
        unzip \
        zip \
        ca-certificates \
        gnupg \
        lsb-release \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Cosign
RUN curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" \
    && mv cosign-linux-amd64 /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype for vulnerability scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install golangci-lint
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v1.55.2

# Install air for live reloading
RUN go install github.com/cosmtrek/air@latest

# Install mockgen
RUN go install github.com/golang/mock/mockgen@latest

# Install goimports
RUN go install golang.org/x/tools/cmd/goimports@latest

# Install swag for API documentation
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Install gotestsum for better test output
RUN go install gotest.tools/gotestsum@latest

# Install staticcheck
RUN go install honnef.co/go/tools/cmd/staticcheck@latest

# Install govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# Set up development aliases and functions
RUN echo 'alias ll="ls -alF"' >> /home/vscode/.bashrc \
    && echo 'alias la="ls -A"' >> /home/vscode/.bashrc \
    && echo 'alias l="ls -CF"' >> /home/vscode/.bashrc \
    && echo 'alias grep="grep --color=auto"' >> /home/vscode/.bashrc \
    && echo 'alias fgrep="fgrep --color=auto"' >> /home/vscode/.bashrc \
    && echo 'alias egrep="egrep --color=auto"' >> /home/vscode/.bashrc

# Create common directories
RUN mkdir -p /workspace/bin \
    && mkdir -p /workspace/tmp \
    && chown -R vscode:vscode /workspace

# Set up git safe directory
RUN git config --global --add safe.directory /workspace

USER vscode

# Install Node.js tools globally
RUN npm install -g \
    prettier \
    eslint \
    @typescript-eslint/parser \
    @typescript-eslint/eslint-plugin \
    typescript \
    ts-node \
    nodemon \
    concurrently

# Set up Go environment
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

WORKDIR /workspace