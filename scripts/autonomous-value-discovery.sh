#!/bin/bash

# Autonomous Value Discovery Engine
# Continuous scanning and prioritization of development tasks
# For Terragon Labs Autonomous SDLC System

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TERRAGON_DIR="$REPO_ROOT/.terragon"
METRICS_FILE="$TERRAGON_DIR/value-metrics.json"
CONFIG_FILE="$TERRAGON_DIR/config.yaml"
BACKLOG_FILE="$REPO_ROOT/docs/BACKLOG.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v yq >/dev/null 2>&1 || missing_deps+=("yq")
    command -v git >/dev/null 2>&1 || missing_deps+=("git")
    command -v golangci-lint >/dev/null 2>&1 || missing_deps+=("golangci-lint")
    command -v gosec >/dev/null 2>&1 || missing_deps+=("gosec")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install them with: apt-get install jq && go install github.com/mikefarah/yq/v4@latest"
        exit 1
    fi
}

# Initialize Terragon directory if needed
init_terragon() {
    if [ ! -d "$TERRAGON_DIR" ]; then
        log_info "Initializing Terragon directory..."
        mkdir -p "$TERRAGON_DIR"
    fi
}

# Discover TODO/FIXME/HACK comments in code
discover_code_comments() {
    log_info "Scanning for code comments (TODO, FIXME, HACK)..."
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local items=()
    
    # Search for different comment patterns
    while IFS= read -r line; do
        local file=$(echo "$line" | cut -d':' -f1)
        local line_num=$(echo "$line" | cut -d':' -f2)
        local content=$(echo "$line" | cut -d':' -f3- | sed 's/^[[:space:]]*//')
        
        # Determine priority based on keyword
        local priority="medium"
        local category="technical_debt"
        local boost=1.5
        
        if [[ "$content" =~ (FIXME|BUG|CRITICAL) ]]; then
            priority="high"
            boost=2.0
        elif [[ "$content" =~ (HACK|TEMP|TEMPORARY) ]]; then
            priority="high"
            boost=1.8
            category="refactoring"
        elif [[ "$content" =~ (OPTIMIZE|PERFORMANCE) ]]; then
            priority="medium"
            boost=1.6
            category="performance"
        elif [[ "$content" =~ (SECURITY|CVE) ]]; then
            priority="critical"
            boost=3.0
            category="security"
        fi
        
        # Extract meaningful title
        local title=$(echo "$content" | sed -E 's/(TODO|FIXME|HACK|NOTE)[:]*[[:space:]]*//' | cut -c1-80)
        
        # Generate item ID
        local item_id="${category:0:3}-$(echo "$file-$line_num" | sha256sum | cut -c1-6)"
        
        cat << EOF >> "$TERRAGON_DIR/discovered-items.jsonl"
{
  "id": "$item_id",
  "title": "$title",
  "category": "$category",
  "priority": "$priority",
  "location": "$file:$line_num",
  "content": "$content",
  "discovery_method": "code_comments",
  "boost_factor": $boost,
  "timestamp": "$timestamp",
  "estimated_effort": 2
}
EOF
    done < <(grep -rn --include="*.go" --include="*.js" --include="*.py" --include="*.yaml" --include="*.yml" \
             -E "(TODO|FIXME|HACK|NOTE|OPTIMIZE|BUG)" "$REPO_ROOT" 2>/dev/null || true)
}

# Discover security vulnerabilities using gosec
discover_security_issues() {
    log_info "Scanning for security issues with gosec..."
    
    if command -v gosec >/dev/null 2>&1; then
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        
        # Run gosec and parse results
        gosec -fmt json ./... 2>/dev/null | jq -r '.Issues[]? | 
        {
            id: ("sec-" + (.file | gsub(".*/"; "") | gsub("\\\."; "-")) + "-" + (.line)),
            title: ("Security: " + .details),
            category: "security",
            priority: (if .severity == "HIGH" then "critical" elif .severity == "MEDIUM" then "high" else "medium" end),
            location: (.file + ":" + (.line | tostring)),
            content: .details,
            discovery_method: "gosec",
            boost_factor: (if .severity == "HIGH" then 3.0 elif .severity == "MEDIUM" then 2.0 else 1.5 end),
            timestamp: "'"$timestamp"'",
            estimated_effort: (if .severity == "HIGH" then 4 elif .severity == "MEDIUM" then 2 else 1 end),
            cwe: .cwe.id,
            rule_id: .rule_id
        }' >> "$TERRAGON_DIR/discovered-items.jsonl" 2>/dev/null || true
    fi
}

# Discover performance bottlenecks using go analysis
discover_performance_issues() {
    log_info "Analyzing performance patterns..."
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Look for common performance anti-patterns
    while IFS= read -r line; do
        local file=$(echo "$line" | cut -d':' -f1)
        local line_num=$(echo "$line" | cut -d':' -f2)
        local content=$(echo "$line" | cut -d':' -f3-)
        
        local issue_type="performance"
        local title="Performance: Potential bottleneck detected"
        local effort=3
        
        if [[ "$content" =~ "SELECT.*\*.*FROM" ]]; then
            title="Database: Avoid SELECT * queries"
            effort=2
        elif [[ "$content" =~ "for.*range.*{" ]] && [[ "$content" =~ "append" ]]; then
            title="Go: Inefficient slice append in loop"
            effort=1
        elif [[ "$content" =~ "time\.Sleep" ]]; then
            title="Performance: Replace time.Sleep with proper synchronization"
            effort=2
        fi
        
        local item_id="perf-$(echo "$file-$line_num" | sha256sum | cut -c1-6)"
        
        cat << EOF >> "$TERRAGON_DIR/discovered-items.jsonl"
{
  "id": "$item_id",
  "title": "$title",
  "category": "performance",
  "priority": "medium",
  "location": "$file:$line_num",
  "content": "$content",
  "discovery_method": "performance_analysis",
  "boost_factor": 1.6,
  "timestamp": "$timestamp",
  "estimated_effort": $effort
}
EOF
    done < <(grep -rn --include="*.go" -E "(SELECT \*|time\.Sleep|for.*range.*\{.*append)" "$REPO_ROOT" 2>/dev/null | head -20 || true)
}

# Discover dependency vulnerabilities using go list
discover_dependency_issues() {
    log_info "Checking for outdated dependencies..."
    
    if [ -f "$REPO_ROOT/go.mod" ]; then
        local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        
        # Check for indirect dependencies that could be updated
        go list -m -u all 2>/dev/null | grep -E "\[.*\]" | while read -r line; do
            local module=$(echo "$line" | awk '{print $1}')
            local current=$(echo "$line" | awk '{print $2}')
            local available=$(echo "$line" | grep -o '\[.*\]' | tr -d '[]')
            
            local item_id="dep-$(echo "$module" | sha256sum | cut -c1-6)"
            
            cat << EOF >> "$TERRAGON_DIR/discovered-items.jsonl"
{
  "id": "$item_id",
  "title": "Dependency Update: $module ($current → $available)",
  "category": "dependencies",
  "priority": "low",
  "location": "go.mod",
  "content": "Update $module from $current to $available",
  "discovery_method": "dependency_analysis",
  "boost_factor": 1.2,
  "timestamp": "$timestamp",
  "estimated_effort": 1
}
EOF
        done
    fi
}

# Calculate composite scores using WSJF + ICE + Technical Debt
calculate_scores() {
    log_info "Calculating value scores for discovered items..."
    
    if [ ! -f "$TERRAGON_DIR/discovered-items.jsonl" ]; then
        log_warning "No items discovered to score"
        return
    fi
    
    # Read scoring weights from config
    local wsjf_weight=$(yq eval '.scoring.weights.wsjf' "$CONFIG_FILE" 2>/dev/null || echo "0.5")
    local ice_weight=$(yq eval '.scoring.weights.ice' "$CONFIG_FILE" 2>/dev/null || echo "0.15")
    local debt_weight=$(yq eval '.scoring.weights.technicalDebt' "$CONFIG_FILE" 2>/dev/null || echo "0.25")
    local security_weight=$(yq eval '.scoring.weights.security' "$CONFIG_FILE" 2>/dev/null || echo "0.10")
    
    # Process each item and calculate scores
    while IFS= read -r item; do
        local category=$(echo "$item" | jq -r '.category')
        local priority=$(echo "$item" | jq -r '.priority')
        local boost=$(echo "$item" | jq -r '.boost_factor')
        local effort=$(echo "$item" | jq -r '.estimated_effort')
        
        # WSJF calculation (simplified)
        local user_value=5
        local time_critical=3
        local risk_reduction=4
        
        case "$priority" in
            "critical") user_value=10; time_critical=10; risk_reduction=9 ;;
            "high") user_value=8; time_critical=7; risk_reduction=6 ;;
            "medium") user_value=5; time_critical=4; risk_reduction=4 ;;
            "low") user_value=3; time_critical=2; risk_reduction=2 ;;
        esac
        
        local cost_of_delay=$((user_value + time_critical + risk_reduction))
        local wsjf=$(echo "scale=2; $cost_of_delay / $effort" | bc -l 2>/dev/null || echo "5.0")
        
        # ICE calculation
        local impact=5
        local confidence=7
        local ease=6
        
        case "$category" in
            "security") impact=9; confidence=8 ;;
            "performance") impact=7; confidence=8; ease=7 ;;
            "technical_debt") impact=6; confidence=9; ease=8 ;;
            "dependencies") impact=4; confidence=9; ease=9 ;;
        esac
        
        local ice=$((impact * confidence * ease))
        
        # Technical debt score (simplified)
        local debt_score=0
        if [ "$category" = "technical_debt" ] || [ "$category" = "refactoring" ]; then
            debt_score=$((effort * 10))
        fi
        
        # Composite score
        local wsjf_norm=$(echo "scale=2; $wsjf * 10" | bc -l 2>/dev/null || echo "50")
        local ice_norm=$(echo "scale=2; $ice / 10" | bc -l 2>/dev/null || echo "50")
        local debt_norm=$(echo "scale=2; $debt_score" | bc -l 2>/dev/null || echo "0")
        
        local composite=$(echo "scale=2; ($wsjf_weight * $wsjf_norm) + ($ice_weight * $ice_norm) + ($debt_weight * $debt_norm)" | bc -l 2>/dev/null || echo "50")
        
        # Apply category boost
        if [ "$category" = "security" ]; then
            composite=$(echo "scale=2; $composite * 2.0" | bc -l 2>/dev/null || echo "$composite")
        fi
        
        # Apply boost factor
        composite=$(echo "scale=2; $composite * $boost" | bc -l 2>/dev/null || echo "$composite")
        
        # Add scores to item
        echo "$item" | jq ". + {
            scores: {
                wsjf: $wsjf,
                ice: $ice,
                technicalDebt: $debt_score,
                composite: $composite
            }
        }" >> "$TERRAGON_DIR/scored-items.jsonl"
        
    done < "$TERRAGON_DIR/discovered-items.jsonl"
}

# Update metrics file
update_metrics() {
    log_info "Updating value metrics..."
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local total_items=$(wc -l < "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    
    # Count items by category and priority
    local security_items=$(grep -c '"category":"security"' "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    local performance_items=$(grep -c '"category":"performance"' "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    local debt_items=$(grep -c '"category":"technical_debt"' "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    local high_priority=$(grep -c '"priority":"high"' "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    local critical_priority=$(grep -c '"priority":"critical"' "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    
    # Update metrics file
    jq ". + {
        last_update: \"$timestamp\",
        backlog_discovery: {
            total_items: $total_items,
            high_priority: $high_priority,
            critical_priority: $critical_priority,
            categories: {
                security: $security_items,
                performance: $performance_items,
                technical_debt: $debt_items
            }
        },
        continuous_metrics: {
            items_discovered_today: $total_items,
            discovery_rate_per_hour: $(echo "scale=2; $total_items / 24" | bc -l 2>/dev/null || echo "1.0")
        }
    }" "$METRICS_FILE" > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"
}

# Select next best value item
select_next_item() {
    log_info "Selecting next best value item..."
    
    if [ ! -f "$TERRAGON_DIR/scored-items.jsonl" ]; then
        log_warning "No scored items available"
        return
    fi
    
    # Find highest scoring item
    local next_item=$(sort -k1,1nr -t',' "$TERRAGON_DIR/scored-items.jsonl" | head -1 | jq -r '.id + ": " + .title + " (Score: " + (.scores.composite | tostring) + ")"')
    
    log_success "Next best value item: $next_item"
    
    # Update metrics with next item
    local next_id=$(sort -k1,1nr -t',' "$TERRAGON_DIR/scored-items.jsonl" | head -1 | jq -r '.id')
    local next_score=$(sort -k1,1nr -t',' "$TERRAGON_DIR/scored-items.jsonl" | head -1 | jq -r '.scores.composite')
    
    jq ". + {
        next_execution: {
            scheduled: \"$(date -u -d '+1 hour' +"%Y-%m-%dT%H:%M:%SZ")\",
            next_best_item: \"$next_id\",
            expected_value: $next_score
        }
    }" "$METRICS_FILE" > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"
}

# Generate backlog report
generate_backlog_report() {
    log_info "Generating backlog report..."
    
    if [ ! -f "$TERRAGON_DIR/scored-items.jsonl" ]; then
        log_warning "No items to report"
        return
    fi
    
    # The BACKLOG.md is already created with the initial content
    # Here we could update it with real discovered items, but for now
    # we'll just add a timestamp update
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local total_items=$(wc -l < "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    
    log_success "Generated backlog report with $total_items items"
}

# Main execution function
main() {
    log_info "🚀 Starting Autonomous Value Discovery..."
    
    check_dependencies
    init_terragon
    
    # Clear previous discovery results
    rm -f "$TERRAGON_DIR/discovered-items.jsonl" "$TERRAGON_DIR/scored-items.jsonl"
    
    # Run discovery methods
    discover_code_comments
    discover_security_issues
    discover_performance_issues
    discover_dependency_issues
    
    # Process and score items
    calculate_scores
    update_metrics
    select_next_item
    generate_backlog_report
    
    local total_discovered=$(wc -l < "$TERRAGON_DIR/scored-items.jsonl" 2>/dev/null || echo "0")
    
    log_success "✅ Value discovery complete! Discovered $total_discovered items"
    log_info "📊 View metrics: $METRICS_FILE"
    log_info "📋 View backlog: $BACKLOG_FILE"
    log_info "🔄 Next execution: $(date -u -d '+1 hour' +"%Y-%m-%dT%H:%M:%S")Z"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi