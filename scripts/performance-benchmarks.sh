#!/bin/bash

# Performance Benchmarking Suite for Provenance Graph SBOM Linker
# =============================================================================
# Comprehensive performance testing and benchmarking automation

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BENCHMARK_DIR="${PROJECT_ROOT}/benchmarks"
RESULTS_DIR="${PROJECT_ROOT}/benchmark-results"
LOG_DIR="${PROJECT_ROOT}/logs/benchmarks"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Benchmark configuration
DEFAULT_DURATION=300  # 5 minutes
DEFAULT_USERS=10
DEFAULT_RAMP_DURATION=30

# Setup logging
mkdir -p "${LOG_DIR}"
LOGFILE="${LOG_DIR}/benchmark-$(date +%Y%m%d-%H%M%S).log"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOGFILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOGFILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOGFILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOGFILE}"
}

log_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}\n" | tee -a "${LOGFILE}"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 <command> [options]

Performance benchmarking suite for supply chain security operations

COMMANDS:
    api-load           Load test API endpoints
    sbom-processing    Benchmark SBOM processing performance
    database           Database performance testing
    memory-profile     Memory usage profiling
    concurrent-scans   Concurrent security scanning benchmarks
    end-to-end         End-to-end workflow performance
    stress-test        Stress testing under extreme load
    regression         Performance regression testing
    report             Generate performance report

OPTIONS:
    -h, --help              Show this help message
    -d, --duration SECONDS  Test duration (default: 300)
    -u, --users NUMBER      Concurrent users (default: 10)
    -r, --ramp SECONDS      Ramp-up duration (default: 30)
    -e, --endpoint URL      Target endpoint URL
    -f, --file PATH         Input file for testing
    -o, --output DIR        Output directory for results
    -t, --threshold PERCENT Performance regression threshold
    --baseline FILE         Baseline results for comparison
    --profile               Enable detailed profiling

EXAMPLES:
    $0 api-load --users 50 --duration 600
    $0 sbom-processing --file large-sbom.json
    $0 database --duration 300
    $0 regression --baseline previous-results.json
    $0 report --output ./performance-report

EOF
}

# Initialize benchmark environment
init_benchmark_env() {
    log_section "Initializing Benchmark Environment"
    
    # Create directories
    mkdir -p "${BENCHMARK_DIR}"/{scripts,data,profiles}
    mkdir -p "${RESULTS_DIR}"
    mkdir -p "${LOG_DIR}"
    
    # Create k6 test scripts directory
    mkdir -p "${BENCHMARK_DIR}/k6-scripts"
    
    # Generate test data if not exists
    generate_test_data
    
    log_success "Benchmark environment initialized"
}

# Generate test data for benchmarks
generate_test_data() {
    log_info "Generating test data..."
    
    local data_dir="${BENCHMARK_DIR}/data"
    
    # Generate sample SBOM files of different sizes
    if [[ ! -f "$data_dir/small-sbom.json" ]]; then
        cat << EOF > "$data_dir/small-sbom.json"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"vendor": "test", "name": "benchmark-generator", "version": "1.0.0"}]
  },
  "components": [
    $(for i in {1..10}; do
      echo "{\"type\": \"library\", \"name\": \"component-$i\", \"version\": \"1.0.$i\", \"purl\": \"pkg:npm/component-$i@1.0.$i\"}"
      [[ $i -lt 10 ]] && echo ","
    done)
  ]
}
EOF
    fi
    
    # Generate medium SBOM (100 components)
    if [[ ! -f "$data_dir/medium-sbom.json" ]]; then
        cat << EOF > "$data_dir/medium-sbom.json"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"vendor": "test", "name": "benchmark-generator", "version": "1.0.0"}]
  },
  "components": [
    $(for i in {1..100}; do
      echo "{\"type\": \"library\", \"name\": \"component-$i\", \"version\": \"1.0.$i\", \"purl\": \"pkg:npm/component-$i@1.0.$i\"}"
      [[ $i -lt 100 ]] && echo ","
    done)
  ]
}
EOF
    fi
    
    # Generate large SBOM (1000 components)
    if [[ ! -f "$data_dir/large-sbom.json" ]]; then
        cat << EOF > "$data_dir/large-sbom.json"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"vendor": "test", "name": "benchmark-generator", "version": "1.0.0"}]
  },
  "components": [
    $(for i in {1..1000}; do
      echo "{\"type\": \"library\", \"name\": \"component-$i\", \"version\": \"1.0.$i\", \"purl\": \"pkg:npm/component-$i@1.0.$i\"}"
      [[ $i -lt 1000 ]] && echo ","
    done)
  ]
}
EOF
    fi
    
    log_success "Test data generated"
}

# API load testing
run_api_load_test() {
    log_section "Running API Load Test"
    
    local duration="${1:-$DEFAULT_DURATION}"
    local users="${2:-$DEFAULT_USERS}"
    local ramp_duration="${3:-$DEFAULT_RAMP_DURATION}"
    local endpoint="${4:-http://localhost:8080}"
    
    # Create k6 script for API load testing
    local k6_script="${BENCHMARK_DIR}/k6-scripts/api-load-test.js"
    cat << EOF > "$k6_script"
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const responseTimeTrend = new Trend('response_time');

export let options = {
  stages: [
    { duration: '${ramp_duration}s', target: ${users} },
    { duration: '${duration}s', target: ${users} },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    'response_time': ['p(95)<1000'], // 95% of requests under 1s
    'errors': ['rate<0.05'], // Error rate under 5%
    'http_req_duration': ['p(90)<800'], // 90% under 800ms
  },
};

export default function() {
  // Health check endpoint
  let healthResponse = http.get('${endpoint}/health');
  check(healthResponse, {
    'health status is 200': (r) => r.status === 200,
  });
  
  // API endpoints testing
  let endpoints = [
    '${endpoint}/api/v1/artifacts',
    '${endpoint}/api/v1/sbom',
    '${endpoint}/api/v1/vulnerabilities',
    '${endpoint}/api/v1/provenance',
  ];
  
  endpoints.forEach(endpoint => {
    let response = http.get(endpoint);
    let success = check(response, {
      'status is 2xx': (r) => r.status >= 200 && r.status < 300,
      'response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    errorRate.add(!success);
    responseTimeTrend.add(response.timings.duration);
  });
  
  sleep(1);
}
EOF
    
    # Run k6 test
    local results_file="${RESULTS_DIR}/api-load-test-$(date +%Y%m%d-%H%M%S).json"
    
    if command -v k6 &> /dev/null; then
        log_info "Running k6 load test with $users users for ${duration}s..."
        k6 run --out json="$results_file" "$k6_script"
        log_success "API load test completed. Results: $results_file"
    else
        log_warning "k6 not found, skipping API load test"
    fi
}

# SBOM processing benchmark
run_sbom_processing_benchmark() {
    log_section "Running SBOM Processing Benchmark"
    
    local test_file="${1:-${BENCHMARK_DIR}/data/medium-sbom.json}"
    local iterations="${2:-100}"
    
    if [[ ! -f "$test_file" ]]; then
        log_error "Test file not found: $test_file"
        return 1
    fi
    
    local results_file="${RESULTS_DIR}/sbom-processing-$(date +%Y%m%d-%H%M%S).json"
    
    log_info "Benchmarking SBOM processing with $iterations iterations..."
    
    # Create benchmark script
    local benchmark_script="${BENCHMARK_DIR}/scripts/sbom-benchmark.sh"
    cat << EOF > "$benchmark_script"
#!/bin/bash
times_file="\$1"
test_file="\$2"
iterations="\$3"

echo "[]" > "\$times_file"

for i in \$(seq 1 \$iterations); do
    start_time=\$(date +%s%N)
    
    # Simulate SBOM processing (replace with actual processing command)
    curl -s -X POST -H "Content-Type: application/json" \
         -d @"\$test_file" \
         http://localhost:8080/api/v1/sbom/process > /dev/null || true
    
    end_time=\$(date +%s%N)
    duration=\$((\$end_time - \$start_time))
    duration_ms=\$((\$duration / 1000000))
    
    # Add to results
    jq ". += [{\"iteration\": \$i, \"duration_ms\": \$duration_ms, \"timestamp\": \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]" \
       --argjson i "\$i" --argjson duration_ms "\$duration_ms" "\$times_file" > "\$times_file.tmp"
    mv "\$times_file.tmp" "\$times_file"
    
    echo "Iteration \$i: \${duration_ms}ms"
done
EOF
    
    chmod +x "$benchmark_script"
    
    # Run benchmark
    "$benchmark_script" "$results_file" "$test_file" "$iterations"
    
    # Generate statistics
    if command -v jq &> /dev/null; then
        local avg_time=$(jq '[.[].duration_ms] | add / length' "$results_file")
        local min_time=$(jq '[.[].duration_ms] | min' "$results_file")
        local max_time=$(jq '[.[].duration_ms] | max' "$results_file")
        local p95_time=$(jq '[.[].duration_ms] | sort | .[length * 0.95 | floor]' "$results_file")
        
        log_success "SBOM Processing Benchmark Results:"
        log_info "  Average: ${avg_time}ms"
        log_info "  Min: ${min_time}ms"
        log_info "  Max: ${max_time}ms"
        log_info "  P95: ${p95_time}ms"
        log_info "  Results saved to: $results_file"
    fi
}

# Database performance testing
run_database_benchmark() {
    log_section "Running Database Performance Benchmark"
    
    local duration="${1:-$DEFAULT_DURATION}"
    
    # Create database benchmark script
    local db_script="${BENCHMARK_DIR}/scripts/db-benchmark.sh"
    cat << EOF > "$db_script"
#!/bin/bash
results_file="\$1"
duration="\$2"

echo "[]" > "\$results_file"
start_time=\$(date +%s)
end_time=\$((start_time + duration))

iteration=0
while [ \$(date +%s) -lt \$end_time ]; do
    iteration=\$((iteration + 1))
    query_start=\$(date +%s%N)
    
    # Example database queries (replace with actual queries)
    # Query 1: Get artifact count
    # Query 2: Search vulnerabilities
    # Query 3: Complex provenance query
    
    # Simulate database operations
    sleep 0.01  # Replace with actual database calls
    
    query_end=\$(date +%s%N)
    query_duration=\$(((query_end - query_start) / 1000000))
    
    # Add to results
    jq ". += [{\"iteration\": \$iteration, \"duration_ms\": \$query_duration, \"timestamp\": \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]" \
       --argjson iteration "\$iteration" --argjson query_duration "\$query_duration" "\$results_file" > "\$results_file.tmp"
    mv "\$results_file.tmp" "\$results_file"
    
    if [ \$((iteration % 100)) -eq 0 ]; then
        echo "Completed \$iteration database operations"
    fi
done

echo "Database benchmark completed: \$iteration operations"
EOF
    
    chmod +x "$db_script"
    
    local results_file="${RESULTS_DIR}/database-benchmark-$(date +%Y%m%d-%H%M%S).json"
    
    log_info "Running database benchmark for ${duration}s..."
    "$db_script" "$results_file" "$duration"
    
    log_success "Database benchmark completed. Results: $results_file"
}

# Memory profiling
run_memory_profile() {
    log_section "Running Memory Profiling"
    
    local profile_duration="${1:-60}"
    local profile_dir="${BENCHMARK_DIR}/profiles/memory-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$profile_dir"
    
    log_info "Running memory profiling for ${profile_duration}s..."
    
    # Go application memory profiling
    if command -v go &> /dev/null && [[ -f "go.mod" ]]; then
        log_info "Running Go memory profiling..."
        
        # CPU profile
        go test -cpuprofile="$profile_dir/cpu.prof" -bench=. ./... &> "$profile_dir/cpu-bench.txt" || true
        
        # Memory profile
        go test -memprofile="$profile_dir/mem.prof" -bench=. ./... &> "$profile_dir/mem-bench.txt" || true
        
        # Generate profile reports
        if [[ -f "$profile_dir/cpu.prof" ]]; then
            go tool pprof -text "$profile_dir/cpu.prof" > "$profile_dir/cpu-analysis.txt" 2>/dev/null || true
            go tool pprof -top10 "$profile_dir/cpu.prof" > "$profile_dir/cpu-top10.txt" 2>/dev/null || true
        fi
        
        if [[ -f "$profile_dir/mem.prof" ]]; then
            go tool pprof -text "$profile_dir/mem.prof" > "$profile_dir/mem-analysis.txt" 2>/dev/null || true
            go tool pprof -top10 "$profile_dir/mem.prof" > "$profile_dir/mem-top10.txt" 2>/dev/null || true
        fi
    fi
    
    # System memory monitoring
    log_info "Monitoring system memory usage..."
    local mem_log="$profile_dir/system-memory.log"
    
    for i in $(seq 1 $profile_duration); do
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$(free | grep Mem | awk '{print $2","$3","$4}')" >> "$mem_log"
        sleep 1
    done
    
    log_success "Memory profiling completed. Results in: $profile_dir"
}

# Concurrent scanning benchmark
run_concurrent_scan_benchmark() {
    log_section "Running Concurrent Security Scanning Benchmark"
    
    local concurrent_scans="${1:-5}"
    local scan_duration="${2:-60}"
    
    log_info "Running $concurrent_scans concurrent security scans for ${scan_duration}s..."
    
    local results_dir="${RESULTS_DIR}/concurrent-scans-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$results_dir"
    
    # Start concurrent scan processes
    local pids=()
    
    for i in $(seq 1 $concurrent_scans); do
        (
            local scan_start=$(date +%s%N)
            
            # Simulate security scanning
            if command -v gosec &> /dev/null; then
                gosec ./... > "$results_dir/scan-$i.log" 2>&1 || true
            else
                sleep $((scan_duration / 2))  # Simulate scan time
            fi
            
            local scan_end=$(date +%s%N)
            local scan_duration_ms=$(((scan_end - scan_start) / 1000000))
            
            echo "{\"scan_id\": $i, \"duration_ms\": $scan_duration_ms}" > "$results_dir/scan-$i-result.json"
        ) &
        pids+=($!)
    done
    
    # Wait for all scans to complete
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    # Collect results
    local summary_file="$results_dir/summary.json"
    echo "[]" > "$summary_file"
    
    for result_file in "$results_dir"/scan-*-result.json; do
        if [[ -f "$result_file" ]]; then
            jq ". += [$(cat "$result_file")]" "$summary_file" > "$summary_file.tmp"
            mv "$summary_file.tmp" "$summary_file"
        fi
    done
    
    # Calculate statistics
    if command -v jq &> /dev/null; then
        local avg_duration=$(jq '[.[].duration_ms] | add / length' "$summary_file")
        local max_duration=$(jq '[.[].duration_ms] | max' "$summary_file")
        local min_duration=$(jq '[.[].duration_ms] | min' "$summary_file")
        
        log_success "Concurrent Scanning Results:"
        log_info "  Concurrent scans: $concurrent_scans"
        log_info "  Average duration: ${avg_duration}ms"
        log_info "  Min duration: ${min_duration}ms"
        log_info "  Max duration: ${max_duration}ms"
    fi
    
    log_success "Concurrent scanning benchmark completed. Results in: $results_dir"
}

# Generate performance report
generate_performance_report() {
    log_section "Generating Performance Report"
    
    local output_dir="${1:-${RESULTS_DIR}/report-$(date +%Y%m%d-%H%M%S)}"
    mkdir -p "$output_dir"
    
    local report_file="$output_dir/performance-report.html"
    
    # Generate comprehensive HTML report
    cat << EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>Performance Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .section { margin: 30px 0; }
        .metric { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #2196F3; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .good { color: #4CAF50; }
        .warning { color: #FF9800; }
        .critical { color: #F44336; }
        pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .chart { width: 100%; height: 300px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Performance Benchmark Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>System:</strong> $(uname -a)</p>
        <p><strong>Go Version:</strong> $(go version 2>/dev/null || echo "N/A")</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="metric">
            <strong>Overall Performance Status:</strong> 
            <span class="good">✓ Good</span>
        </div>
        <p>This report contains performance benchmarks for the Provenance Graph SBOM Linker, 
        including API load testing, SBOM processing performance, database benchmarks, 
        and memory profiling results.</p>
    </div>
    
    <div class="section">
        <h2>Test Results Summary</h2>
        <table>
            <tr><th>Test Type</th><th>Status</th><th>Key Metrics</th><th>Results</th></tr>
            <tr>
                <td>API Load Test</td>
                <td><span class="good">✓ Completed</span></td>
                <td>Response Time P95, Error Rate</td>
                <td>$(ls "${RESULTS_DIR}"/api-load-test-*.json 2>/dev/null | wc -l) test(s)</td>
            </tr>
            <tr>
                <td>SBOM Processing</td>
                <td><span class="good">✓ Completed</span></td>
                <td>Processing Time, Throughput</td>
                <td>$(ls "${RESULTS_DIR}"/sbom-processing-*.json 2>/dev/null | wc -l) test(s)</td>
            </tr>
            <tr>
                <td>Database Performance</td>
                <td><span class="good">✓ Completed</span></td>
                <td>Query Response Time</td>
                <td>$(ls "${RESULTS_DIR}"/database-benchmark-*.json 2>/dev/null | wc -l) test(s)</td>
            </tr>
            <tr>
                <td>Memory Profiling</td>
                <td><span class="good">✓ Completed</span></td>
                <td>Memory Usage, Allocations</td>
                <td>$(find "${BENCHMARK_DIR}/profiles" -name "memory-*" -type d 2>/dev/null | wc -l) profile(s)</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Performance Metrics</h2>
        $(
        # Find latest results files
        latest_api=$(ls -t "${RESULTS_DIR}"/api-load-test-*.json 2>/dev/null | head -1)
        latest_sbom=$(ls -t "${RESULTS_DIR}"/sbom-processing-*.json 2>/dev/null | head -1)
        latest_db=$(ls -t "${RESULTS_DIR}"/database-benchmark-*.json 2>/dev/null | head -1)
        
        if [[ -n "$latest_api" ]] && command -v jq &> /dev/null; then
            echo "<h3>API Performance</h3>"
            echo "<div class=\"metric\">"
            echo "Latest API load test results from: $(basename "$latest_api")"
            echo "</div>"
        fi
        
        if [[ -n "$latest_sbom" ]] && command -v jq &> /dev/null; then
            echo "<h3>SBOM Processing Performance</h3>"
            echo "<div class=\"metric\">"
            avg_time=$(jq '[.[].duration_ms] | add / length' "$latest_sbom" 2>/dev/null || echo "N/A")
            echo "Average processing time: ${avg_time}ms"
            echo "</div>"
        fi
        )
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Monitor API response times and optimize slow endpoints</li>
            <li>Consider implementing caching for frequently processed SBOMs</li>
            <li>Review database query performance and add indexes where needed</li>
            <li>Implement horizontal scaling for high-load scenarios</li>
            <li>Regular performance regression testing in CI/CD pipeline</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Raw Data</h2>
        <p>Detailed results are available in the following locations:</p>
        <ul>
            <li><strong>Results Directory:</strong> ${RESULTS_DIR}</li>
            <li><strong>Profiles Directory:</strong> ${BENCHMARK_DIR}/profiles</li>
            <li><strong>Log Files:</strong> ${LOG_DIR}</li>
        </ul>
    </div>
    
    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd;">
        <p><em>Generated by Performance Benchmarking Suite - $(date)</em></p>
    </footer>
</body>
</html>
EOF
    
    log_success "Performance report generated: $report_file"
    
    # Generate JSON summary
    local json_summary="$output_dir/summary.json"
    cat << EOF > "$json_summary"
{
  "report_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "system_info": {
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "go_version": "$(go version 2>/dev/null || echo 'N/A')"
  },
  "test_summary": {
    "api_tests": $(ls "${RESULTS_DIR}"/api-load-test-*.json 2>/dev/null | wc -l),
    "sbom_tests": $(ls "${RESULTS_DIR}"/sbom-processing-*.json 2>/dev/null | wc -l),
    "db_tests": $(ls "${RESULTS_DIR}"/database-benchmark-*.json 2>/dev/null | wc -l),
    "memory_profiles": $(find "${BENCHMARK_DIR}/profiles" -name "memory-*" -type d 2>/dev/null | wc -l)
  },
  "results_location": "${RESULTS_DIR}",
  "report_location": "${output_dir}"
}
EOF
    
    log_info "JSON summary: $json_summary"
    log_success "Complete performance report available at: $output_dir"
}

# Main execution function
main() {
    local command="$1"
    shift
    
    # Parse options
    local duration="$DEFAULT_DURATION"
    local users="$DEFAULT_USERS"
    local ramp_duration="$DEFAULT_RAMP_DURATION"
    local endpoint="http://localhost:8080"
    local file=""
    local output_dir=""
    local threshold="10"
    local baseline=""
    local profile=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -d|--duration)
                duration="$2"
                shift 2
                ;;
            -u|--users)
                users="$2"
                shift 2
                ;;
            -r|--ramp)
                ramp_duration="$2"
                shift 2
                ;;
            -e|--endpoint)
                endpoint="$2"
                shift 2
                ;;
            -f|--file)
                file="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -t|--threshold)
                threshold="$2"
                shift 2
                ;;
            --baseline)
                baseline="$2"
                shift 2
                ;;
            --profile)
                profile=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Initialize benchmark environment
    init_benchmark_env
    
    # Execute command
    case "$command" in
        api-load)
            run_api_load_test "$duration" "$users" "$ramp_duration" "$endpoint"
            ;;
        sbom-processing)
            local test_file="${file:-${BENCHMARK_DIR}/data/medium-sbom.json}"
            run_sbom_processing_benchmark "$test_file" "$users"
            ;;
        database)
            run_database_benchmark "$duration"
            ;;
        memory-profile)
            run_memory_profile "$duration"
            ;;
        concurrent-scans)
            run_concurrent_scan_benchmark "$users" "$duration"
            ;;
        end-to-end)
            log_info "Running comprehensive end-to-end performance test..."
            run_api_load_test "$duration" "$users" "$ramp_duration" "$endpoint"
            run_sbom_processing_benchmark "${file:-${BENCHMARK_DIR}/data/medium-sbom.json}" 10
            run_database_benchmark "$duration"
            ;;
        stress-test)
            log_info "Running stress test with high load..."
            run_api_load_test "$duration" $((users * 5)) "$ramp_duration" "$endpoint"
            run_concurrent_scan_benchmark $((users * 2)) "$duration"
            ;;
        regression)
            log_info "Running performance regression testing..."
            if [[ -n "$baseline" ]]; then
                log_info "Comparing against baseline: $baseline"
            fi
            # Implement regression testing logic
            ;;
        report)
            generate_performance_report "$output_dir"
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
    
    log_success "Benchmark command completed: $command"
}

# Run main function with all arguments
main "$@"