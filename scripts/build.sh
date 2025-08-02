#!/bin/bash

# =============================================================================
# Build Script for Provenance Graph SBOM Linker
# =============================================================================
# Comprehensive build automation with security and compliance features

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Build configuration
readonly PROJECT_NAME="provenance-graph-sbom-linker"
readonly BINARY_NAME="provenance-linker"
readonly CLI_BINARY_NAME="provenance-cli"
readonly MODULE_NAME="github.com/your-org/provenance-graph-sbom-linker"

# Directories
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly BUILD_DIR="${PROJECT_ROOT}/build"
readonly BIN_DIR="${PROJECT_ROOT}/bin"
readonly DIST_DIR="${PROJECT_ROOT}/dist"

# Build metadata
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'unknown')}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
BRANCH="${BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')}"
BUILD_USER="${BUILD_USER:-$(whoami)}"
BUILD_HOST="${BUILD_HOST:-$(hostname)}"

# Build flags
ENABLE_CGO="${ENABLE_CGO:-1}"
BUILD_TAGS="${BUILD_TAGS:-}"
LDFLAGS="${LDFLAGS:-}"
GCFLAGS="${GCFLAGS:-}"
ASMFLAGS="${ASMFLAGS:-}"

# Security and compliance
ENABLE_SBOM="${ENABLE_SBOM:-true}"
ENABLE_SIGNING="${ENABLE_SIGNING:-false}"
ENABLE_ATTESTATION="${ENABLE_ATTESTATION:-false}"
COSIGN_KEY_PATH="${COSIGN_KEY_PATH:-}"
COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"

# Docker configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io/your-org}"
DOCKER_TAG="${DOCKER_TAG:-${VERSION}}"
DOCKER_PLATFORMS="${DOCKER_PLATFORMS:-linux/amd64,linux/arm64}"
ENABLE_DOCKER_BUILDX="${ENABLE_DOCKER_BUILDX:-true}"

# Output configuration
VERBOSE="${VERBOSE:-false}"
QUIET="${QUIET:-false}"

# Functions
# =============================================================================

log() {
    if [[ "${QUIET}" != "true" ]]; then
        echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}" >&2
    fi
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $*${NC}" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*${NC}" >&2
}

fatal() {
    error "$*"
    exit 1
}

verbose() {
    if [[ "${VERBOSE}" == "true" ]]; then
        echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] DEBUG: $*${NC}" >&2
    fi
}

check_dependencies() {
    log "Checking build dependencies..."
    
    local deps=("go" "git")
    
    if [[ "${ENABLE_SBOM}" == "true" ]]; then
        deps+=("syft")
    fi
    
    if [[ "${ENABLE_SIGNING}" == "true" ]]; then
        deps+=("cosign")
    fi
    
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" >/dev/null 2>&1; then
            fatal "Required dependency '${dep}' not found"
        fi
        verbose "Found ${dep}: $(command -v "${dep}")"
    done
    
    # Check Go version
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log "Go version: ${go_version}"
    
    # Verify we're in a Go module
    if [[ ! -f "go.mod" ]]; then
        fatal "go.mod not found. Please run from project root."
    fi
}

setup_directories() {
    log "Setting up build directories..."
    
    mkdir -p "${BUILD_DIR}" "${BIN_DIR}" "${DIST_DIR}"
    
    # Clean previous builds if requested
    if [[ "${CLEAN:-false}" == "true" ]]; then
        log "Cleaning previous builds..."
        rm -rf "${BUILD_DIR}"/* "${BIN_DIR}"/* "${DIST_DIR}"/*
    fi
}

calculate_ldflags() {
    local ldflags=""
    
    # Version information
    ldflags+="-X '${MODULE_NAME}/internal/version.Version=${VERSION}' "
    ldflags+="-X '${MODULE_NAME}/internal/version.Commit=${COMMIT}' "
    ldflags+="-X '${MODULE_NAME}/internal/version.Date=${DATE}' "
    ldflags+="-X '${MODULE_NAME}/internal/version.Branch=${BRANCH}' "
    ldflags+="-X '${MODULE_NAME}/internal/version.BuildUser=${BUILD_USER}' "
    ldflags+="-X '${MODULE_NAME}/internal/version.BuildHost=${BUILD_HOST}' "
    
    # Build optimization
    ldflags+="-w -s "  # Strip debug info and symbol table
    
    # Additional ldflags
    if [[ -n "${LDFLAGS}" ]]; then
        ldflags+="${LDFLAGS} "
    fi
    
    echo "${ldflags}"
}

build_binary() {
    local cmd_path="$1"
    local output_path="$2"
    local description="$3"
    
    log "Building ${description}..."
    
    local ldflags
    ldflags=$(calculate_ldflags)
    
    local build_args=(
        "build"
        "-ldflags=${ldflags}"
        "-o" "${output_path}"
    )
    
    # Add build tags if specified
    if [[ -n "${BUILD_TAGS}" ]]; then
        build_args+=("-tags" "${BUILD_TAGS}")
    fi
    
    # Add gcflags if specified
    if [[ -n "${GCFLAGS}" ]]; then
        build_args+=("-gcflags" "${GCFLAGS}")
    fi
    
    # Add asmflags if specified
    if [[ -n "${ASMFLAGS}" ]]; then
        build_args+=("-asmflags" "${ASMFLAGS}")
    fi
    
    # Enable verbose output if requested
    if [[ "${VERBOSE}" == "true" ]]; then
        build_args+=("-v")
    fi
    
    # Add command path
    build_args+=("${cmd_path}")
    
    # Set CGO environment
    export CGO_ENABLED="${ENABLE_CGO}"
    
    verbose "Go build command: go ${build_args[*]}"
    
    if ! go "${build_args[@]}"; then
        fatal "Failed to build ${description}"
    fi
    
    log "Successfully built ${description}: ${output_path}"
}

build_binaries() {
    log "Building application binaries..."
    
    # Build server binary
    build_binary \
        "./cmd/server" \
        "${BIN_DIR}/${BINARY_NAME}" \
        "server binary"
    
    # Build CLI binary
    build_binary \
        "./cmd/cli" \
        "${BIN_DIR}/${CLI_BINARY_NAME}" \
        "CLI binary"
}

cross_compile() {
    log "Cross-compiling for multiple platforms..."
    
    local platforms=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    
    for platform in "${platforms[@]}"; do
        local goos="${platform%/*}"
        local goarch="${platform#*/}"
        local suffix=""
        
        if [[ "${goos}" == "windows" ]]; then
            suffix=".exe"
        fi
        
        local output_dir="${DIST_DIR}/${goos}-${goarch}"
        mkdir -p "${output_dir}"
        
        log "Building for ${platform}..."
        
        # Build server
        GOOS="${goos}" GOARCH="${goarch}" build_binary \
            "./cmd/server" \
            "${output_dir}/${BINARY_NAME}${suffix}" \
            "server binary for ${platform}"
        
        # Build CLI
        GOOS="${goos}" GOARCH="${goarch}" build_binary \
            "./cmd/cli" \
            "${output_dir}/${CLI_BINARY_NAME}${suffix}" \
            "CLI binary for ${platform}"
        
        # Create archive
        local archive_name="${PROJECT_NAME}_${VERSION}_${goos}_${goarch}"
        if [[ "${goos}" == "windows" ]]; then
            (cd "${output_dir}" && zip -r "../${archive_name}.zip" .)
        else
            tar -czf "${DIST_DIR}/${archive_name}.tar.gz" -C "${output_dir}" .
        fi
    done
}

generate_sbom() {
    if [[ "${ENABLE_SBOM}" != "true" ]]; then
        verbose "SBOM generation disabled"
        return 0
    fi
    
    log "Generating SBOM..."
    
    local sbom_formats=("cyclonedx-json" "spdx-json" "syft-json")
    
    for format in "${sbom_formats[@]}"; do
        local output_file="${DIST_DIR}/sbom.${format##*-}"
        
        verbose "Generating SBOM in ${format} format..."
        
        if ! syft . -o "${format}=${output_file}"; then
            warn "Failed to generate SBOM in ${format} format"
        else
            log "Generated SBOM: ${output_file}"
        fi
    done
}

build_docker_image() {
    log "Building Docker image..."
    
    local image_tag="${DOCKER_REGISTRY}/${PROJECT_NAME}:${DOCKER_TAG}"
    local latest_tag="${DOCKER_REGISTRY}/${PROJECT_NAME}:latest"
    
    local docker_args=(
        "build"
        "--build-arg" "VERSION=${VERSION}"
        "--build-arg" "COMMIT=${COMMIT}"
        "--build-arg" "DATE=${DATE}"
        "--tag" "${image_tag}"
        "--tag" "${latest_tag}"
    )
    
    # Add labels for better metadata
    docker_args+=(
        "--label" "org.opencontainers.image.title=${PROJECT_NAME}"
        "--label" "org.opencontainers.image.version=${VERSION}"
        "--label" "org.opencontainers.image.created=${DATE}"
        "--label" "org.opencontainers.image.revision=${COMMIT}"
        "--label" "org.opencontainers.image.source=https://github.com/your-org/${PROJECT_NAME}"
        "--label" "org.opencontainers.image.url=https://github.com/your-org/${PROJECT_NAME}"
        "--label" "org.opencontainers.image.vendor=Your Organization"
        "--label" "org.opencontainers.image.licenses=Apache-2.0"
    )
    
    # Use buildx for multi-platform builds if enabled
    if [[ "${ENABLE_DOCKER_BUILDX}" == "true" ]]; then
        docker_args=("buildx" "build" "--platform" "${DOCKER_PLATFORMS}" "${docker_args[@]:1}")
    fi
    
    docker_args+=(".")
    
    verbose "Docker build command: docker ${docker_args[*]}"
    
    if ! docker "${docker_args[@]}"; then
        fatal "Failed to build Docker image"
    fi
    
    log "Successfully built Docker image: ${image_tag}"
}

sign_artifacts() {
    if [[ "${ENABLE_SIGNING}" != "true" ]]; then
        verbose "Artifact signing disabled"
        return 0
    fi
    
    if [[ -z "${COSIGN_KEY_PATH}" ]]; then
        warn "COSIGN_KEY_PATH not set, skipping signing"
        return 0
    fi
    
    log "Signing artifacts..."
    
    # Sign binaries
    for binary in "${BIN_DIR}"/*; do
        if [[ -f "${binary}" ]]; then
            log "Signing ${binary}..."
            if ! cosign sign-blob --key "${COSIGN_KEY_PATH}" --output-signature "${binary}.sig" "${binary}"; then
                warn "Failed to sign ${binary}"
            fi
        fi
    done
    
    # Sign container image if built
    local image_tag="${DOCKER_REGISTRY}/${PROJECT_NAME}:${DOCKER_TAG}"
    if docker image inspect "${image_tag}" >/dev/null 2>&1; then
        log "Signing container image ${image_tag}..."
        if ! cosign sign --key "${COSIGN_KEY_PATH}" "${image_tag}"; then
            warn "Failed to sign container image"
        fi
    fi
}

generate_attestation() {
    if [[ "${ENABLE_ATTESTATION}" != "true" ]]; then
        verbose "Attestation generation disabled"
        return 0
    fi
    
    log "Generating attestations..."
    
    # Generate SLSA provenance
    local provenance_file="${DIST_DIR}/slsa-provenance.json"
    
    cat > "${provenance_file}" << EOF
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [],
  "predicate": {
    "builder": {
      "id": "https://github.com/your-org/${PROJECT_NAME}/actions/workflows/build.yml@${COMMIT}"
    },
    "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/your-org/${PROJECT_NAME}.git",
        "digest": {"sha1": "${COMMIT}"},
        "entryPoint": "scripts/build.sh"
      }
    },
    "metadata": {
      "buildInvocationId": "$(uuidgen)",
      "buildStartedOn": "${DATE}",
      "buildFinishedOn": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "completeness": {
        "parameters": true,
        "environment": false,
        "materials": true
      },
      "reproducible": false
    },
    "materials": [
      {
        "uri": "git+https://github.com/your-org/${PROJECT_NAME}.git",
        "digest": {"sha1": "${COMMIT}"}
      }
    ]
  }
}
EOF
    
    log "Generated SLSA provenance: ${provenance_file}"
}

run_tests() {
    log "Running tests..."
    
    if ! make test; then
        fatal "Tests failed"
    fi
    
    log "All tests passed"
}

run_security_scan() {
    log "Running security scans..."
    
    # Run gosec
    if command -v gosec >/dev/null 2>&1; then
        if ! gosec ./...; then
            warn "Security issues found by gosec"
        fi
    else
        warn "gosec not found, skipping Go security scan"
    fi
    
    # Scan Docker image if built
    local image_tag="${DOCKER_REGISTRY}/${PROJECT_NAME}:${DOCKER_TAG}"
    if docker image inspect "${image_tag}" >/dev/null 2>&1; then
        if command -v trivy >/dev/null 2>&1; then
            log "Scanning Docker image with Trivy..."
            if ! trivy image "${image_tag}"; then
                warn "Security issues found in Docker image"
            fi
        else
            warn "trivy not found, skipping container security scan"
        fi
    fi
}

print_summary() {
    log "Build completed successfully!"
    echo
    echo "Build Summary:"
    echo "=============="
    echo "Version:     ${VERSION}"
    echo "Commit:      ${COMMIT}"
    echo "Date:        ${DATE}"
    echo "Branch:      ${BRANCH}"
    echo "Build User:  ${BUILD_USER}"
    echo "Build Host:  ${BUILD_HOST}"
    echo
    echo "Artifacts:"
    echo "----------"
    if [[ -d "${BIN_DIR}" ]]; then
        find "${BIN_DIR}" -type f -exec basename {} \; | sed 's/^/  - /'
    fi
    if [[ -d "${DIST_DIR}" ]]; then
        find "${DIST_DIR}" -type f -name "*.tar.gz" -o -name "*.zip" | sed 's/^/  - /'
    fi
    echo
}

cleanup() {
    verbose "Cleaning up temporary files..."
    # Add any cleanup logic here
}

show_help() {
    cat << EOF
Build script for ${PROJECT_NAME}

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -q, --quiet             Suppress output except errors
    -c, --clean             Clean previous builds
    --cross-compile         Enable cross-compilation for multiple platforms
    --docker                Build Docker image
    --sign                  Sign artifacts (requires COSIGN_KEY_PATH)
    --attest                Generate attestations
    --test                  Run tests before building
    --security-scan         Run security scans
    --no-sbom              Disable SBOM generation

ENVIRONMENT VARIABLES:
    VERSION                 Version string (default: git describe)
    COMMIT                  Git commit hash (default: git rev-parse)
    BUILD_TAGS              Go build tags
    ENABLE_CGO              Enable CGO (default: 1)
    COSIGN_KEY_PATH         Path to Cosign signing key
    DOCKER_REGISTRY         Docker registry (default: ghcr.io/your-org)
    DOCKER_TAG              Docker tag (default: VERSION)

EXAMPLES:
    $0                      # Basic build
    $0 --cross-compile      # Cross-compile for all platforms
    $0 --docker --sign      # Build and sign Docker image
    $0 --test --security-scan # Run tests and security scans

EOF
}

main() {
    # Parse command line arguments
    local cross_compile=false
    local build_docker=false
    local run_tests_flag=false
    local run_security_scan_flag=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                ;;
            -q|--quiet)
                QUIET=true
                ;;
            -c|--clean)
                CLEAN=true
                ;;
            --cross-compile)
                cross_compile=true
                ;;
            --docker)
                build_docker=true
                ;;
            --sign)
                ENABLE_SIGNING=true
                ;;
            --attest)
                ENABLE_ATTESTATION=true
                ;;
            --test)
                run_tests_flag=true
                ;;
            --security-scan)
                run_security_scan_flag=true
                ;;
            --no-sbom)
                ENABLE_SBOM=false
                ;;
            *)
                fatal "Unknown option: $1"
                ;;
        esac
        shift
    done
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    # Change to project root
    cd "${PROJECT_ROOT}"
    
    # Main build flow
    check_dependencies
    setup_directories
    
    if [[ "${run_tests_flag}" == "true" ]]; then
        run_tests
    fi
    
    build_binaries
    
    if [[ "${cross_compile}" == "true" ]]; then
        cross_compile
    fi
    
    if [[ "${build_docker}" == "true" ]]; then
        build_docker_image
    fi
    
    generate_sbom
    sign_artifacts
    generate_attestation
    
    if [[ "${run_security_scan_flag}" == "true" ]]; then
        run_security_scan
    fi
    
    print_summary
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi