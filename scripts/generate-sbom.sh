#!/bin/bash

# SBOM Generation Script for Provenance Graph SBOM Linker
# =============================================================================
# Generates comprehensive Software Bill of Materials in multiple formats

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMP_DIR=$(mktemp -d)
TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
EXIT_CODE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# SBOM output directory
SBOM_DIR="${PROJECT_ROOT}/sbom"
mkdir -p "$SBOM_DIR"

# Configuration
SBOM_NAME="provenance-graph-sbom-linker"
SBOM_VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
SBOM_NAMESPACE="https://github.com/your-org/provenance-graph-sbom-linker"

# Functions
log_info() {
    echo -e "${BLUE}INFO:${NC} $1"
}

log_success() {
    echo -e "${GREEN}SUCCESS:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

cleanup() {
    rm -rf "${TEMP_DIR}"
}

trap cleanup EXIT

check_tools() {
    log_info "Checking required tools..."
    
    local missing_tools=()
    
    # Check Syft for general SBOM generation
    if ! command -v syft &> /dev/null; then
        missing_tools+=("syft")
    fi
    
    # Check CycloneDX CLI
    if ! command -v cyclonedx &> /dev/null; then
        missing_tools+=("cyclonedx")
    fi
    
    # Check Go for Go module analysis
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "Missing tools: ${missing_tools[*]}"
        install_tools "${missing_tools[@]}"
    else
        log_success "All required tools are available"
    fi
}

install_tools() {
    local tools=("$@")
    
    for tool in "${tools[@]}"; do
        case "$tool" in
            "syft")
                log_info "Installing Syft..."
                curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
                ;;
            "cyclonedx")
                log_info "Installing CycloneDX CLI..."
                if command -v npm &> /dev/null; then
                    npm install -g @cyclonedx/cli
                else
                    log_warning "NPM not available, skipping CycloneDX CLI installation"
                fi
                ;;
            *)
                log_warning "Don't know how to install $tool, please install manually"
                ;;
        esac
    done
}

generate_go_sbom() {
    log_info "Generating Go module SBOM..."
    
    cd "${PROJECT_ROOT}"
    
    # Generate CycloneDX format using Syft
    syft packages . \
        --output cyclonedx-json="${SBOM_DIR}/${SBOM_NAME}-go-${TIMESTAMP}.cyclonedx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers go-module-binary,go-module-file
    
    log_success "Go SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-go-${TIMESTAMP}.cyclonedx.json"
    
    # Generate SPDX format
    syft packages . \
        --output spdx-json="${SBOM_DIR}/${SBOM_NAME}-go-${TIMESTAMP}.spdx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers go-module-binary,go-module-file
    
    log_success "Go SPDX SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-go-${TIMESTAMP}.spdx.json"
}

generate_npm_sbom() {
    log_info "Generating NPM package SBOM..."
    
    if [[ ! -f "${PROJECT_ROOT}/package.json" ]]; then
        log_info "No package.json found, skipping NPM SBOM generation"
        return 0
    fi
    
    cd "${PROJECT_ROOT}"
    
    # Generate NPM SBOM using Syft
    syft packages . \
        --output cyclonedx-json="${SBOM_DIR}/${SBOM_NAME}-npm-${TIMESTAMP}.cyclonedx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers npm-package-lock,yarn-lock,pnpm-lock
    
    log_success "NPM SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-npm-${TIMESTAMP}.cyclonedx.json"
    
    # Generate using CycloneDX CLI if available
    if command -v cyclonedx &> /dev/null; then
        cyclonedx npm \
            --input-file package.json \
            --output-file "${SBOM_DIR}/${SBOM_NAME}-npm-cyclonedx-${TIMESTAMP}.json" \
            --output-format json \
            --include-dev
        
        log_success "NPM CycloneDX SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-npm-cyclonedx-${TIMESTAMP}.json"
    fi
}

generate_container_sbom() {
    log_info "Generating container SBOM..."
    
    local image_name="${SBOM_NAME}:latest"
    
    # Check if Docker image exists
    if ! docker image inspect "$image_name" &> /dev/null; then
        log_warning "Docker image $image_name not found, building..."
        if [[ -f "${PROJECT_ROOT}/Dockerfile" ]]; then
            docker build -t "$image_name" "$PROJECT_ROOT"
        else
            log_warning "No Dockerfile found, skipping container SBOM generation"
            return 0
        fi
    fi
    
    # Generate container SBOM
    syft packages "$image_name" \
        --output cyclonedx-json="${SBOM_DIR}/${SBOM_NAME}-container-${TIMESTAMP}.cyclonedx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION"
    
    log_success "Container SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-container-${TIMESTAMP}.cyclonedx.json"
    
    # Generate SPDX format for container
    syft packages "$image_name" \
        --output spdx-json="${SBOM_DIR}/${SBOM_NAME}-container-${TIMESTAMP}.spdx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION"
    
    log_success "Container SPDX SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-container-${TIMESTAMP}.spdx.json"
}

generate_comprehensive_sbom() {
    log_info "Generating comprehensive project SBOM..."
    
    cd "${PROJECT_ROOT}"
    
    # Generate comprehensive SBOM including all components
    syft packages . \
        --output cyclonedx-json="${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.cyclonedx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers all
    
    log_success "Comprehensive SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.cyclonedx.json"
    
    # Generate SPDX format
    syft packages . \
        --output spdx-json="${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.spdx.json" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers all
    
    log_success "Comprehensive SPDX SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.spdx.json"
    
    # Generate text table format for human readability
    syft packages . \
        --output table="${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.txt" \
        --source-name "$SBOM_NAME" \
        --source-version "$SBOM_VERSION" \
        --catalogers all
    
    log_success "Human-readable SBOM generated: ${SBOM_DIR}/${SBOM_NAME}-complete-${TIMESTAMP}.txt"
}

create_latest_symlinks() {
    log_info "Creating latest SBOM symlinks..."
    
    cd "$SBOM_DIR"
    
    # Create symlinks for latest versions
    for file in *-${TIMESTAMP}.*; do
        if [[ -f "$file" ]]; then
            local latest_name=${file//-${TIMESTAMP}/}
            ln -sf "$file" "$latest_name"
            log_success "Created symlink: $latest_name -> $file"
        fi
    done
}

validate_sboms() {
    log_info "Validating generated SBOMs..."
    
    local validation_errors=0
    
    # Validate CycloneDX files
    for file in "${SBOM_DIR}"/*.cyclonedx.json; do
        if [[ -f "$file" ]]; then
            if ! jq empty "$file" 2>/dev/null; then
                log_error "Invalid JSON in $file"
                ((validation_errors++))
            else
                log_success "✓ $file is valid JSON"
            fi
        fi
    done
    
    # Validate SPDX files
    for file in "${SBOM_DIR}"/*.spdx.json; do
        if [[ -f "$file" ]]; then
            if ! jq empty "$file" 2>/dev/null; then
                log_error "Invalid JSON in $file"
                ((validation_errors++))
            else
                log_success "✓ $file is valid JSON"
            fi
        fi
    done
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "SBOM validation failed with $validation_errors errors"
        EXIT_CODE=1
    else
        log_success "All SBOMs validated successfully"
    fi
}

generate_sbom_metadata() {
    log_info "Generating SBOM metadata..."
    
    local metadata_file="${SBOM_DIR}/metadata.json"
    
    cat > "$metadata_file" << EOF
{
  "project": {
    "name": "$SBOM_NAME",
    "version": "$SBOM_VERSION",
    "namespace": "$SBOM_NAMESPACE",
    "repository": "$(git remote get-url origin 2>/dev/null || echo 'unknown')",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
  },
  "generation": {
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "tool": "syft",
    "version": "$(syft version 2>/dev/null | head -1 || echo 'unknown')",
    "formats": ["cyclonedx-json", "spdx-json", "table"]
  },
  "files": [
EOF
    
    local first=true
    for file in "${SBOM_DIR}"/*.{cyclonedx.json,spdx.json,txt}; do
        if [[ -f "$file" ]]; then
            local basename=$(basename "$file")
            if [[ "$first" == true ]]; then
                first=false
            else
                echo "," >> "$metadata_file"
            fi
            echo -n "    {" >> "$metadata_file"
            echo -n "\"name\": \"$basename\", " >> "$metadata_file"
            echo -n "\"size\": $(stat -c%s "$file"), " >> "$metadata_file"
            echo -n "\"sha256\": \"$(sha256sum "$file" | cut -d' ' -f1)\"" >> "$metadata_file"
            echo -n "}" >> "$metadata_file"
        fi
    done
    
    cat >> "$metadata_file" << EOF

  ]
}
EOF
    
    log_success "SBOM metadata generated: $metadata_file"
}

sign_sboms() {
    log_info "Signing SBOMs (if Cosign is available)..."
    
    if ! command -v cosign &> /dev/null; then
        log_warning "Cosign not available, skipping SBOM signing"
        return 0
    fi
    
    # Check if signing key is available
    if [[ ! -f "${HOME}/.cosign/cosign.key" ]] && [[ -z "${COSIGN_PRIVATE_KEY:-}" ]]; then
        log_warning "No Cosign private key found, skipping SBOM signing"
        return 0
    fi
    
    cd "$SBOM_DIR"
    
    for file in *.cyclonedx.json *.spdx.json; do
        if [[ -f "$file" ]]; then
            cosign sign-blob --bundle "${file}.cosign.bundle" "$file"
            log_success "Signed SBOM: $file"
        fi
    done
}

create_sbom_archive() {
    log_info "Creating SBOM archive..."
    
    local archive_name="${SBOM_NAME}-sbom-${TIMESTAMP}.tar.gz"
    local archive_path="${PROJECT_ROOT}/${archive_name}"
    
    cd "$PROJECT_ROOT"
    tar -czf "$archive_path" -C "$SBOM_DIR" .
    
    log_success "SBOM archive created: $archive_path"
    
    # Create latest symlink
    ln -sf "$archive_name" "${PROJECT_ROOT}/${SBOM_NAME}-sbom-latest.tar.gz"
    log_success "Latest SBOM archive: ${PROJECT_ROOT}/${SBOM_NAME}-sbom-latest.tar.gz"
}

main() {
    log_info "Starting SBOM generation for Provenance Graph SBOM Linker"
    
    check_tools
    generate_go_sbom
    generate_npm_sbom
    generate_container_sbom
    generate_comprehensive_sbom
    create_latest_symlinks
    validate_sboms
    generate_sbom_metadata
    sign_sboms
    create_sbom_archive
    
    if [[ $EXIT_CODE -eq 0 ]]; then
        log_success "SBOM generation completed successfully"
        log_info "Generated SBOMs are available in: $SBOM_DIR"
    else
        log_error "SBOM generation failed"
    fi
    
    exit $EXIT_CODE
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi