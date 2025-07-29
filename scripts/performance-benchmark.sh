#!/bin/bash
# Performance Benchmarking Script
# =============================================================================

set -euo pipefail

# Configuration
BENCHMARK_DIR="benchmark-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="${BENCHMARK_DIR}/benchmark_${TIMESTAMP}.json"
GO_BENCH_FLAGS="-benchmem -count=5 -timeout=30m"
LOAD_TEST_DURATION="5m"
LOAD_TEST_VUS="50"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Create benchmark directory
mkdir -p "${BENCHMARK_DIR}"

# Initialize results JSON
cat > "${RESULT_FILE}" << EOF
{
  "timestamp": "${TIMESTAMP}",
  "git_commit": "$(git rev-parse HEAD)",
  "git_branch": "$(git rev-parse --abbrev-ref HEAD)",
  "go_version": "$(go version | awk '{print $3}')",
  "benchmarks": {
    "unit": {},
    "integration": {},
    "load": {},
    "memory": {},
    "cpu": {}
  }
}
EOF

# Function to update JSON results
update_results() {
    local section="$1"
    local key="$2"
    local value="$3"
    
    # Use jq to update the JSON file
    jq ".benchmarks.${section}.${key} = ${value}" "${RESULT_FILE}" > "${RESULT_FILE}.tmp" && mv "${RESULT_FILE}.tmp" "${RESULT_FILE}"
}

# Function to run Go benchmarks
run_go_benchmarks() {
    log "Running Go unit benchmarks..."
    
    local bench_output
    bench_output=$(go test ${GO_BENCH_FLAGS} -bench=. ./pkg/... ./internal/... 2>&1 || true)
    
    # Parse benchmark results and update JSON
    echo "${bench_output}" | grep "Benchmark" | while read -r line; do
        if [[ $line =~ BenchmarkSBOMParsing.*-.*[[:space:]]+([0-9]+)[[:space:]]+([0-9.]+)[[:space:]]+ns/op[[:space:]]+([0-9]+)[[:space:]]+B/op[[:space:]]+([0-9]+)[[:space:]]+allocs/op ]]; then
            local ops_per_sec=$((1000000000 / ${BASH_REMATCH[2]%.*}))
            update_results "unit" "sbom_parsing_ops_per_sec" "${ops_per_sec}"
            update_results "unit" "sbom_parsing_ns_per_op" "${BASH_REMATCH[2]}"
            update_results "unit" "sbom_parsing_bytes_per_op" "${BASH_REMATCH[3]}"
            update_results "unit" "sbom_parsing_allocs_per_op" "${BASH_REMATCH[4]}"
        fi
        
        if [[ $line =~ BenchmarkProvenance.*-.*[[:space:]]+([0-9]+)[[:space:]]+([0-9.]+)[[:space:]]+ns/op[[:space:]]+([0-9]+)[[:space:]]+B/op[[:space:]]+([0-9]+)[[:space:]]+allocs/op ]]; then
            local ops_per_sec=$((1000000000 / ${BASH_REMATCH[2]%.*}))
            update_results "unit" "provenance_ops_per_sec" "${ops_per_sec}"
            update_results "unit" "provenance_ns_per_op" "${BASH_REMATCH[2]}"
            update_results "unit" "provenance_bytes_per_op" "${BASH_REMATCH[3]}"
            update_results "unit" "provenance_allocs_per_op" "${BASH_REMATCH[4]}"
        fi
    done
    
    log_success "Go benchmarks completed"
}

# Function to run integration benchmarks
run_integration_benchmarks() {
    log "Running integration benchmarks..."
    
    # Start required services
    docker-compose -f docker-compose.test.yml up -d neo4j redis
    
    # Wait for services to be ready
    sleep 30
    
    local start_time
    local end_time
    local duration
    
    # Test Neo4j write performance
    start_time=$(date +%s.%N)
    go test -tags=integration -run=BenchmarkNeo4jWrite ./test/integration/... -count=1 || true
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    update_results "integration" "neo4j_write_duration" "${duration}"
    
    # Test Neo4j read performance
    start_time=$(date +%s.%N)
    go test -tags=integration -run=BenchmarkNeo4jRead ./test/integration/... -count=1 || true
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    update_results "integration" "neo4j_read_duration" "${duration}"
    
    # Cleanup
    docker-compose -f docker-compose.test.yml down
    
    log_success "Integration benchmarks completed"
}

# Function to run load tests
run_load_tests() {
    log "Running load tests..."
    
    # Start the application
    make build
    ./bin/provenance-linker server --config=test/config/benchmark.yaml &
    local server_pid=$!
    
    # Wait for server to start
    sleep 10
    
    # Check if k6 is available
    if command -v k6 >/dev/null 2>&1; then
        # Run k6 load test
        k6 run --duration="${LOAD_TEST_DURATION}" --vus="${LOAD_TEST_VUS}" \
           --out json="${BENCHMARK_DIR}/load_test_${TIMESTAMP}.json" \
           test/load/api_test.js || true
        
        # Parse k6 results
        if [[ -f "${BENCHMARK_DIR}/load_test_${TIMESTAMP}.json" ]]; then
            local avg_response_time
            local p95_response_time
            local throughput
            
            avg_response_time=$(jq -r 'select(.type=="Point" and .metric=="http_req_duration") | .data.value' "${BENCHMARK_DIR}/load_test_${TIMESTAMP}.json" | awk '{sum+=$1; n++} END {if(n>0) print sum/n; else print 0}')
            throughput=$(jq -r 'select(.type=="Point" and .metric=="http_reqs") | .data.value' "${BENCHMARK_DIR}/load_test_${TIMESTAMP}.json" | wc -l)
            
            update_results "load" "avg_response_time_ms" "${avg_response_time}"
            update_results "load" "throughput_rps" "${throughput}"
        fi
    else
        log_warning "k6 not found, skipping load tests"
    fi
    
    # Stop the server
    kill $server_pid || true
    
    log_success "Load tests completed"
}

# Function to run memory profiling
run_memory_profiling() {
    log "Running memory profiling..."
    
    # Run with memory profiling
    go test -memprofile="${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof" \
           -bench=BenchmarkSBOM ./pkg/sbom/... -count=1 || true
    
    if [[ -f "${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof" ]]; then
        # Analyze memory profile
        local mem_analysis
        mem_analysis=$(go tool pprof -text "${BENCHMARK_DIR}/mem_${TIMESTAMP}.prof" | head -20)
        
        # Extract memory usage stats
        local heap_usage
        heap_usage=$(echo "${mem_analysis}" | grep -E "(heap|alloc)" | head -1 | awk '{print $1}' || echo "0")
        update_results "memory" "heap_usage_mb" "${heap_usage}"
    fi
    
    log_success "Memory profiling completed"
}

# Function to run CPU profiling
run_cpu_profiling() {
    log "Running CPU profiling..."
    
    # Run with CPU profiling
    go test -cpuprofile="${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof" \
           -bench=BenchmarkProvenance ./pkg/provenance/... -count=1 || true
    
    if [[ -f "${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof" ]]; then
        # Analyze CPU profile
        local cpu_analysis
        cpu_analysis=$(go tool pprof -text "${BENCHMARK_DIR}/cpu_${TIMESTAMP}.prof" | head -20)
        
        # Extract CPU usage stats
        local cpu_percentage
        cpu_percentage=$(echo "${cpu_analysis}" | grep -E "total" | awk '{print $1}' | tr -d '%' || echo "0")
        update_results "cpu" "cpu_usage_percent" "${cpu_percentage}"
    fi
    
    log_success "CPU profiling completed"
}

# Function to generate benchmark report
generate_report() {
    log "Generating benchmark report..."
    
    local report_file="${BENCHMARK_DIR}/report_${TIMESTAMP}.html"
    
    cat > "${report_file}" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Performance Benchmark Report - ${TIMESTAMP}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
        .metric { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }
        .metric-value { font-size: 1.5em; font-weight: bold; color: #007acc; }
        .metric-label { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Performance Benchmark Report</h1>
        <p><strong>Timestamp:</strong> ${TIMESTAMP}</p>
        <p><strong>Git Commit:</strong> $(git rev-parse HEAD)</p>
        <p><strong>Git Branch:</strong> $(git rev-parse --abbrev-ref HEAD)</p>
        <p><strong>Go Version:</strong> $(go version | awk '{print $3}')</p>
    </div>
    
    <div class="section">
        <h2>Unit Benchmark Results</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value" id="sbom-ops">Loading...</div>
                <div class="metric-label">SBOM Parsing Ops/sec</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="provenance-ops">Loading...</div>
                <div class="metric-label">Provenance Ops/sec</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Integration Test Results</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value" id="neo4j-write">Loading...</div>
                <div class="metric-label">Neo4j Write Duration (s)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="neo4j-read">Loading...</div>
                <div class="metric-label">Neo4j Read Duration (s)</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Load Test Results</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value" id="avg-response">Loading...</div>
                <div class="metric-label">Avg Response Time (ms)</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="throughput">Loading...</div>
                <div class="metric-label">Throughput (RPS)</div>
            </div>
        </div>
    </div>
    
    <script>
        // Load and display benchmark data
        fetch('./benchmark_${TIMESTAMP}.json')
            .then(response => response.json())
            .then(data => {
                document.getElementById('sbom-ops').textContent = data.benchmarks.unit.sbom_parsing_ops_per_sec || 'N/A';
                document.getElementById('provenance-ops').textContent = data.benchmarks.unit.provenance_ops_per_sec || 'N/A';
                document.getElementById('neo4j-write').textContent = parseFloat(data.benchmarks.integration.neo4j_write_duration || 0).toFixed(2);
                document.getElementById('neo4j-read').textContent = parseFloat(data.benchmarks.integration.neo4j_read_duration || 0).toFixed(2);
                document.getElementById('avg-response').textContent = parseFloat(data.benchmarks.load.avg_response_time_ms || 0).toFixed(2);
                document.getElementById('throughput').textContent = data.benchmarks.load.throughput_rps || 'N/A';
            })
            .catch(error => console.error('Error loading benchmark data:', error));
    </script>
</body>
</html>
EOF
    
    log_success "Benchmark report generated: ${report_file}"
}

# Main execution
main() {
    log "Starting performance benchmarking..."
    
    # Check dependencies
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required but not installed. Please install jq first."
        exit 1
    fi
    
    if ! command -v bc >/dev/null 2>&1; then
        log_error "bc is required but not installed. Please install bc first."
        exit 1
    fi
    
    # Run benchmarks
    run_go_benchmarks
    run_integration_benchmarks
    run_load_tests
    run_memory_profiling
    run_cpu_profiling
    
    # Generate report
    generate_report
    
    log_success "All benchmarks completed! Results saved to ${BENCHMARK_DIR}/"
    log "View the report at: ${BENCHMARK_DIR}/report_${TIMESTAMP}.html"
}

# Run if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi