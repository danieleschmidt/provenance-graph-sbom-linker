#!/bin/bash
# =============================================================================
# Build script for Provenance Graph SBOM Linker
# =============================================================================

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${ROOT_DIR}/bin"
DIST_DIR="${ROOT_DIR}/dist"

# Build configuration
BINARY_NAME="provenance-linker"
MODULE_NAME="github.com/your-org/provenance-graph-sbom-linker"

# Version information
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
DATE="${DATE:-$(date -u +'%Y-%m-%dT%H:%M:%SZ')}"

# Build flags
LDFLAGS=(
    "-s" "-w"
    "-X ${MODULE_NAME}/internal/version.Version=${VERSION}"
    "-X ${MODULE_NAME}/internal/version.Commit=${COMMIT}"
    "-X ${MODULE_NAME}/internal/version.Date=${DATE}"
)

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_debug() {
    if [[ "${DEBUG:-}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*"
    fi
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND]

Build script for Provenance Graph SBOM Linker

COMMANDS:
    build           Build binary for current platform (default)
    build-all       Build binaries for all supported platforms
    docker          Build Docker image
    docker-security Build security-hardened Docker image
    clean           Clean build artifacts
    test            Run tests before building
    release         Build release artifacts
    help            Show this help message

OPTIONS:
    -v, --version VERSION    Set version string (default: git describe)
    -o, --output DIR         Set output directory (default: bin/)
    -t, --target PLATFORM    Target platform (e.g., linux/amd64)
    --debug                  Enable debug output
    --no-cache              Disable build cache
    --static                Force static linking
    --race                  Enable race detection
    --tags TAGS             Build tags (comma-separated)

PLATFORMS (for build-all):
    linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64

EXAMPLES:
    $0 build                                    # Build for current platform
    $0 build-all                               # Build for all platforms
    $0 build --target linux/arm64             # Build for specific platform
    $0 docker --version v1.0.0                # Build Docker image with version
    $0 release                                 # Build release artifacts
    $0 test build                              # Run tests then build

EOF
}

# Platform detection
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case $arch in
        x86_64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        armv7l) arch="arm" ;;
        i386) arch="386" ;;
    esac
    
    echo "${os}/${arch}"
}

# Validate environment
validate_environment() {
    log_info "Validating build environment..."
    
    # Check Go version
    if ! command -v go &>/dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_debug "Go version: $go_version"
    
    # Check minimum Go version (1.21)
    if ! printf '%s\n1.21.0\n' "$go_version" | sort -V | head -1 | grep -q "1.21.0"; then
        log_warning "Go version $go_version may not be supported (minimum: 1.21.0)"
    fi
    
    # Check Git (for version information)
    if ! command -v git &>/dev/null; then
        log_warning "Git is not installed - version information will be limited"
    fi
    
    # Check Docker (if building images)
    if [[ "${1:-}" == "docker"* ]] && ! command -v docker &>/dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    log_success "Environment validation passed"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    
    rm -rf "${BUILD_DIR}"
    rm -rf "${DIST_DIR}"
    rm -f coverage.out coverage.html
    
    # Clean Go build cache
    go clean -cache -testcache -modcache
    
    log_success "Clean completed"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    cd "$ROOT_DIR"
    
    # Run unit tests
    go test -v -race -count=1 ./... || {
        log_error "Tests failed"
        exit 1
    }
    
    # Run tests with coverage
    go test -v -race -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    
    local coverage
    coverage=$(go tool cover -func=coverage.out | tail -1 | awk '{print $3}')
    log_info "Test coverage: $coverage"
    
    log_success "All tests passed"
}

# Build for single platform
build_single() {
    local target="${1:-$(detect_platform)}"
    local output_dir="${2:-$BUILD_DIR}"
    local build_tags="${3:-}"
    
    log_info "Building for platform: $target"
    
    # Parse platform
    local goos goarch
    IFS='/' read -r goos goarch <<< "$target"
    
    # Determine binary extension
    local ext=""
    if [[ "$goos" == "windows" ]]; then
        ext=".exe"
    fi
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Set output path
    local output_path="${output_dir}/${BINARY_NAME}-${goos}-${goarch}${ext}"
    if [[ "$target" == "$(detect_platform)" ]]; then
        output_path="${output_dir}/${BINARY_NAME}${ext}"
    fi
    
    # Build flags
    local build_flags=(
        "-ldflags=$(IFS=' '; echo "${LDFLAGS[*]}")"
        "-trimpath"
    )
    
    # Add build tags if specified
    if [[ -n "$build_tags" ]]; then
        build_flags+=("-tags=$build_tags")
    fi
    
    # Add race detection if enabled
    if [[ "${RACE:-}" == "true" ]]; then
        build_flags+=("-race")
    fi
    
    # Force static linking if enabled
    if [[ "${STATIC:-}" == "true" ]]; then
        build_flags+=("-a" "-installsuffix=cgo")
        export CGO_ENABLED=0
    fi
    
    # Build the binary
    cd "$ROOT_DIR"
    
    log_debug "Build command: GOOS=$goos GOARCH=$goarch go build ${build_flags[*]} -o $output_path ./cmd/server"
    
    GOOS="$goos" GOARCH="$goarch" \
        go build "${build_flags[@]}" -o "$output_path" ./cmd/server
    
    # Verify the binary
    if [[ -f "$output_path" ]]; then
        local size
        size=$(du -h "$output_path" | cut -f1)
        log_success "Built $output_path ($size)"
        
        # Run basic validation on native binaries
        if [[ "$target" == "$(detect_platform)" ]] && [[ "${goos}" != "windows" ]]; then
            if "$output_path" version &>/dev/null; then
                log_success "Binary validation passed"
            else
                log_warning "Binary validation failed"
            fi
        fi
    else
        log_error "Build failed - binary not found"
        exit 1
    fi
}

# Build for all supported platforms
build_all() {
    local platforms=(
        "linux/amd64"
        "linux/arm64"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    
    log_info "Building for all platforms..."
    
    mkdir -p "$DIST_DIR"
    
    for platform in "${platforms[@]}"; do
        build_single "$platform" "$DIST_DIR" "$BUILD_TAGS"
    done
    
    log_success "Multi-platform build completed"
    
    # Create checksums
    cd "$DIST_DIR"
    find . -name "${BINARY_NAME}-*" -type f -exec sha256sum {} \; > checksums.txt
    log_info "Checksums created: ${DIST_DIR}/checksums.txt"
}

# Build Docker image
build_docker() {
    local tag="${DOCKER_TAG:-provenance-linker:${VERSION}}"
    local dockerfile="${DOCKERFILE:-Dockerfile}"
    local context="${DOCKER_CONTEXT:-$ROOT_DIR}"
    
    log_info "Building Docker image: $tag"
    
    cd "$ROOT_DIR"
    
    # Build arguments
    local build_args=(
        "--build-arg=VERSION=$VERSION"
        "--build-arg=COMMIT=$COMMIT"
        "--build-arg=DATE=$DATE"
    )
    
    # Add no-cache flag if requested
    if [[ "${NO_CACHE:-}" == "true" ]]; then
        build_args+=("--no-cache")
    fi
    
    # Build the image
    docker build \
        "${build_args[@]}" \
        -t "$tag" \
        -f "$dockerfile" \
        "$context"
    
    # Tag as latest if this is a release
    if [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        docker tag "$tag" "provenance-linker:latest"
        log_info "Tagged as latest"
    fi
    
    log_success "Docker image built: $tag"
}

# Build security-hardened Docker image
build_docker_security() {
    DOCKERFILE="build/Dockerfile.security" build_docker
}

# Create release artifacts
build_release() {
    log_info "Building release artifacts..."
    
    # Clean first
    clean
    
    # Run tests
    run_tests
    
    # Build all platforms
    BUILD_TAGS="release" build_all
    
    # Build Docker images
    build_docker
    build_docker_security
    
    # Create archive files
    cd "$DIST_DIR"
    for binary in ${BINARY_NAME}-*; do
        if [[ -f "$binary" ]] && [[ "$binary" != *.tar.gz ]]; then
            local archive="${binary}.tar.gz"
            tar -czf "$archive" "$binary"
            log_info "Created archive: $archive"
        fi
    done
    
    log_success "Release build completed"
    log_info "Artifacts available in: $DIST_DIR"
}

# Main function
main() {
    local command="build"
    local target=""
    local output_dir=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            build|build-all|docker|docker-security|clean|test|release|help)
                command="$1"
                shift
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -t|--target)
                target="$2"
                shift 2
                ;;
            --debug)
                DEBUG="true"
                shift
                ;;
            --no-cache)
                NO_CACHE="true"
                shift
                ;;
            --static)
                STATIC="true"
                shift
                ;;
            --race)
                RACE="true"
                shift
                ;;
            --tags)
                BUILD_TAGS="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Set default output directory
    if [[ -z "$output_dir" ]]; then
        if [[ "$command" == "build-all" ]]; then
            output_dir="$DIST_DIR"
        else
            output_dir="$BUILD_DIR"
        fi
    fi
    
    # Display build information
    log_info "Provenance Graph SBOM Linker Build Script"
    log_info "Version: $VERSION"
    log_info "Commit: $COMMIT"
    log_info "Date: $DATE"
    log_info "Command: $command"
    [[ -n "$target" ]] && log_info "Target: $target"
    log_info "Output: $output_dir"
    
    # Execute command
    case $command in
        build)
            validate_environment
            build_single "${target:-$(detect_platform)}" "$output_dir" "$BUILD_TAGS"
            ;;
        build-all)
            validate_environment
            build_all
            ;;
        docker)
            validate_environment docker
            build_docker
            ;;
        docker-security)
            validate_environment docker
            build_docker_security
            ;;
        clean)
            clean
            ;;
        test)
            validate_environment
            run_tests
            ;;
        release)
            validate_environment docker
            build_release
            ;;
        help)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"