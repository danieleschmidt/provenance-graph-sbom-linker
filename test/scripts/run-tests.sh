#!/bin/bash

# Test runner script for Provenance Graph SBOM Linker
# This script orchestrates different types of tests and environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"
COVERAGE_DIR="${PROJECT_ROOT}/coverage"
TEST_TIMEOUT="${TEST_TIMEOUT:-300s}"
PARALLEL_TESTS="${PARALLEL_TESTS:-4}"

# Test types
RUN_UNIT="${RUN_UNIT:-true}"
RUN_INTEGRATION="${RUN_INTEGRATION:-false}"
RUN_E2E="${RUN_E2E:-false}"
RUN_PERFORMANCE="${RUN_PERFORMANCE:-false}"
RUN_SECURITY="${RUN_SECURITY:-false}"

# Environment
ENVIRONMENT="${ENVIRONMENT:-local}"
CLEANUP_ON_EXIT="${CLEANUP_ON_EXIT:-true}"

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Test runner for Provenance Graph SBOM Linker

OPTIONS:
    -h, --help              Show this help message
    -u, --unit              Run unit tests only
    -i, --integration       Run integration tests
    -e, --e2e               Run end-to-end tests
    -p, --performance       Run performance tests
    -s, --security          Run security tests
    -a, --all               Run all tests
    -c, --coverage          Generate coverage reports
    -v, --verbose           Verbose output
    --no-cleanup           Don't cleanup test environment on exit
    --parallel N           Number of parallel test processes (default: 4)
    --timeout DURATION     Test timeout (default: 300s)
    --env ENVIRONMENT      Test environment (local|ci|docker, default: local)

ENVIRONMENT VARIABLES:
    TEST_TIMEOUT           Override default test timeout
    PARALLEL_TESTS         Override default parallel test count
    NEO4J_URI             Neo4j connection URI for tests
    REDIS_URL             Redis connection URL for tests
    INTEGRATION_TEST      Set to 'true' to enable integration tests
    E2E_TEST              Set to 'true' to enable E2E tests

EXAMPLES:
    $0 --unit                           # Run only unit tests
    $0 --integration --coverage         # Run integration tests with coverage
    $0 --all --env docker               # Run all tests in Docker environment
    $0 --e2e --verbose --no-cleanup     # Run E2E tests with verbose output, no cleanup

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -u|--unit)
                RUN_UNIT=true
                RUN_INTEGRATION=false
                RUN_E2E=false
                RUN_PERFORMANCE=false
                RUN_SECURITY=false
                shift
                ;;
            -i|--integration)
                RUN_INTEGRATION=true
                shift
                ;;
            -e|--e2e)
                RUN_E2E=true
                shift
                ;;
            -p|--performance)
                RUN_PERFORMANCE=true
                shift
                ;;
            -s|--security)
                RUN_SECURITY=true
                shift
                ;;
            -a|--all)
                RUN_UNIT=true
                RUN_INTEGRATION=true
                RUN_E2E=true
                RUN_PERFORMANCE=true
                RUN_SECURITY=true
                shift
                ;;
            -c|--coverage)
                GENERATE_COVERAGE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --no-cleanup)
                CLEANUP_ON_EXIT=false
                shift
                ;;
            --parallel)
                PARALLEL_TESTS="$2"
                shift 2
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Setup test environment
setup_environment() {
    print_section "Setting up test environment"
    
    # Create directories
    mkdir -p "${TEST_RESULTS_DIR}"
    mkdir -p "${COVERAGE_DIR}"
    
    case "${ENVIRONMENT}" in
        local)
            print_info "Using local test environment"
            ;;
        ci)
            print_info "Using CI test environment"
            export CGO_ENABLED=1
            export GOMAXPROCS=2
            ;;
        docker)
            print_info "Using Docker test environment"
            setup_docker_environment
            ;;
        *)
            print_error "Unknown environment: ${ENVIRONMENT}"
            exit 1
            ;;
    esac
}

# Setup Docker test environment
setup_docker_environment() {
    print_info "Starting Docker test services..."
    
    # Determine which services to start based on test types
    SERVICES=""
    if [[ "${RUN_UNIT}" == "true" ]]; then
        SERVICES+=" neo4j-test redis-test"
    fi
    if [[ "${RUN_INTEGRATION}" == "true" ]]; then
        SERVICES+=" minio-test minio-setup"
    fi
    if [[ "${RUN_E2E}" == "true" ]]; then
        SERVICES+=" jaeger-test prometheus-test github-mock registry-mock"
    fi
    
    # Start services
    docker-compose -f docker-compose.test.yml up -d ${SERVICES}
    
    # Wait for services to be healthy
    print_info "Waiting for services to be ready..."
    docker-compose -f docker-compose.test.yml ps
    
    # Set environment variables for tests
    export NEO4J_URI="bolt://localhost:7688"
    export REDIS_URL="redis://localhost:6380/1"
    export TEST_MINIO_ENDPOINT="localhost:9002"
}

# Cleanup function
cleanup() {
    if [[ "${CLEANUP_ON_EXIT}" == "true" ]]; then
        print_section "Cleaning up test environment"
        
        case "${ENVIRONMENT}" in
            docker)
                print_info "Stopping Docker test services..."
                docker-compose -f docker-compose.test.yml down -v
                ;;
            *)
                print_info "Cleaning up local test data..."
                # Clean up any local test artifacts
                rm -rf /tmp/test-*
                ;;
        esac
    fi
}

# Trap cleanup function
trap cleanup EXIT

# Run unit tests
run_unit_tests() {
    if [[ "${RUN_UNIT}" != "true" ]]; then
        return 0
    fi
    
    print_section "Running Unit Tests"
    
    local test_args=()
    test_args+=("-race")
    test_args+=("-timeout" "${TEST_TIMEOUT}")
    test_args+=("-parallel" "${PARALLEL_TESTS}")
    
    if [[ "${VERBOSE}" == "true" ]]; then
        test_args+=("-v")
    fi
    
    if [[ "${GENERATE_COVERAGE}" == "true" ]]; then
        test_args+=("-coverprofile=${COVERAGE_DIR}/unit-coverage.out")
        test_args+=("-covermode=atomic")
    fi
    
    # Add unit test tag
    test_args+=("-tags=unit")
    
    print_info "Running: go test ${test_args[*]} ./..."
    
    if gotestsum --junitfile "${TEST_RESULTS_DIR}/unit-tests.xml" \
                 --format testname \
                 -- "${test_args[@]}" ./...; then
        print_success "Unit tests passed"
    else
        print_error "Unit tests failed"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    if [[ "${RUN_INTEGRATION}" != "true" ]]; then
        return 0
    fi
    
    print_section "Running Integration Tests"
    
    # Set environment variables for integration tests
    export INTEGRATION_TEST=true
    
    local test_args=()
    test_args+=("-race")
    test_args+=("-timeout" "${TEST_TIMEOUT}")
    test_args+=("-parallel" "${PARALLEL_TESTS}")
    test_args+=("-tags=integration")
    
    if [[ "${VERBOSE}" == "true" ]]; then
        test_args+=("-v")
    fi
    
    if [[ "${GENERATE_COVERAGE}" == "true" ]]; then
        test_args+=("-coverprofile=${COVERAGE_DIR}/integration-coverage.out")
        test_args+=("-covermode=atomic")
    fi
    
    print_info "Running: go test ${test_args[*]} ./test/integration/..."
    
    if gotestsum --junitfile "${TEST_RESULTS_DIR}/integration-tests.xml" \
                 --format testname \
                 -- "${test_args[@]}" ./test/integration/...; then
        print_success "Integration tests passed"
    else
        print_error "Integration tests failed"
        return 1
    fi
}

# Run E2E tests
run_e2e_tests() {
    if [[ "${RUN_E2E}" != "true" ]]; then
        return 0
    fi
    
    print_section "Running End-to-End Tests"
    
    # Set environment variables for E2E tests
    export E2E_TEST=true
    export API_BASE_URL="${API_BASE_URL:-http://localhost:8081/api/v1}"
    
    local test_args=()
    test_args+=("-timeout" "600s")  # Longer timeout for E2E tests
    test_args+=("-tags=e2e")
    
    if [[ "${VERBOSE}" == "true" ]]; then
        test_args+=("-v")
    fi
    
    print_info "Running: go test ${test_args[*]} ./test/e2e/..."
    
    if gotestsum --junitfile "${TEST_RESULTS_DIR}/e2e-tests.xml" \
                 --format testname \
                 -- "${test_args[@]}" ./test/e2e/...; then
        print_success "E2E tests passed"
    else
        print_error "E2E tests failed"
        return 1
    fi
}

# Run performance tests
run_performance_tests() {
    if [[ "${RUN_PERFORMANCE}" != "true" ]]; then
        return 0
    fi
    
    print_section "Running Performance Tests"
    
    # Check if K6 is available
    if ! command -v k6 &> /dev/null; then
        print_warning "K6 not found, skipping performance tests"
        return 0
    fi
    
    local script_dir="${PROJECT_ROOT}/test/performance"
    if [[ ! -d "${script_dir}" ]]; then
        print_warning "Performance test scripts not found, skipping"
        return 0
    fi
    
    export API_URL="${API_BASE_URL:-http://localhost:8081/api/v1}"
    
    for script in "${script_dir}"/*.js; do
        if [[ -f "${script}" ]]; then
            local script_name=$(basename "${script}")
            print_info "Running performance test: ${script_name}"
            
            if k6 run --out json="${TEST_RESULTS_DIR}/performance-${script_name}.json" "${script}"; then
                print_success "Performance test ${script_name} completed"
            else
                print_error "Performance test ${script_name} failed"
                return 1
            fi
        fi
    done
}

# Run security tests
run_security_tests() {
    if [[ "${RUN_SECURITY}" != "true" ]]; then
        return 0
    fi
    
    print_section "Running Security Tests"
    
    # Run gosec
    if command -v gosec &> /dev/null; then
        print_info "Running gosec security scan..."
        if gosec -fmt json -out "${TEST_RESULTS_DIR}/gosec-report.json" ./...; then
            print_success "Gosec scan completed"
        else
            print_warning "Gosec found security issues"
        fi
    fi
    
    # Run govulncheck
    if command -v govulncheck &> /dev/null; then
        print_info "Running govulncheck vulnerability scan..."
        if govulncheck -json ./... > "${TEST_RESULTS_DIR}/govulncheck-report.json"; then
            print_success "Govulncheck scan completed"
        else
            print_warning "Govulncheck found vulnerabilities"
        fi
    fi
    
    # Run trivy on built images
    if command -v trivy &> /dev/null && [[ "${ENVIRONMENT}" == "docker" ]]; then
        print_info "Running Trivy container security scan..."
        if trivy image --format json --output "${TEST_RESULTS_DIR}/trivy-report.json" provenance-linker:test; then
            print_success "Trivy scan completed"
        else
            print_warning "Trivy found security issues"
        fi
    fi
}

# Generate coverage report
generate_coverage_report() {
    if [[ "${GENERATE_COVERAGE}" != "true" ]]; then
        return 0
    fi
    
    print_section "Generating Coverage Report"
    
    # Merge coverage files
    local coverage_files=()
    for file in "${COVERAGE_DIR}"/*-coverage.out; do
        if [[ -f "${file}" ]]; then
            coverage_files+=("${file}")
        fi
    done
    
    if [[ ${#coverage_files[@]} -eq 0 ]]; then
        print_warning "No coverage files found"
        return 0
    fi
    
    # Merge coverage profiles
    print_info "Merging coverage profiles..."
    go tool covdata textfmt -i="${COVERAGE_DIR}" -o="${COVERAGE_DIR}/merged-coverage.out" || \
    gocovmerge "${coverage_files[@]}" > "${COVERAGE_DIR}/merged-coverage.out"
    
    # Generate HTML report
    print_info "Generating HTML coverage report..."
    go tool cover -html="${COVERAGE_DIR}/merged-coverage.out" -o="${COVERAGE_DIR}/coverage.html"
    
    # Generate XML report for CI
    if command -v gocov &> /dev/null && command -v gocov-xml &> /dev/null; then
        print_info "Generating XML coverage report..."
        gocov convert "${COVERAGE_DIR}/merged-coverage.out" | gocov-xml > "${COVERAGE_DIR}/coverage.xml"
    fi
    
    # Show coverage summary
    local coverage_percent=$(go tool cover -func="${COVERAGE_DIR}/merged-coverage.out" | grep total | awk '{print $3}')
    print_success "Total coverage: ${coverage_percent}"
}

# Main function
main() {
    print_section "Provenance Graph SBOM Linker Test Runner"
    
    # Parse arguments
    parse_args "$@"
    
    # Setup environment
    setup_environment
    
    # Run tests
    local exit_code=0
    
    run_unit_tests || exit_code=1
    run_integration_tests || exit_code=1
    run_e2e_tests || exit_code=1
    run_performance_tests || exit_code=1
    run_security_tests || exit_code=1
    
    # Generate coverage report
    generate_coverage_report
    
    # Summary
    print_section "Test Summary"
    if [[ ${exit_code} -eq 0 ]]; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed!"
    fi
    
    print_info "Test results available in: ${TEST_RESULTS_DIR}"
    if [[ "${GENERATE_COVERAGE}" == "true" ]]; then
        print_info "Coverage report available in: ${COVERAGE_DIR}"
    fi
    
    exit ${exit_code}
}

# Run main function with all arguments
main "$@"