#!/bin/bash

# License Check Script for Provenance Graph SBOM Linker
# =============================================================================
# Checks all dependencies for approved licenses and flags any violations

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMP_DIR=$(mktemp -d)
EXIT_CODE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Approved licenses (SPDX identifiers)
APPROVED_LICENSES=(
    "Apache-2.0"
    "MIT"
    "BSD-2-Clause"
    "BSD-3-Clause"
    "ISC"
    "MPL-2.0"
    "CC0-1.0"
    "Unlicense"
    "0BSD"
)

# Licenses requiring manual review
REVIEW_REQUIRED=(
    "LGPL-2.1"
    "LGPL-3.0"
    "EPL-1.0"
    "EPL-2.0"
    "CDDL-1.0"
    "CDDL-1.1"
    "CPL-1.0"
    "IPL-1.0"
)

# Banned licenses
BANNED_LICENSES=(
    "GPL-2.0"
    "GPL-3.0"
    "AGPL-1.0"
    "AGPL-3.0"
    "WTFPL"
    "CNRI-Python"
    "CNRI-Jython"
)

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

check_go_licenses() {
    log_info "Checking Go module licenses..."
    
    cd "${PROJECT_ROOT}"
    
    # Check if go-licenses is installed
    if ! command -v go-licenses &> /dev/null; then
        log_warning "go-licenses not found, installing..."
        go install github.com/google/go-licenses@latest
    fi
    
    # Generate license report
    go-licenses report ./... > "${TEMP_DIR}/go-licenses.json" 2>/dev/null || {
        log_error "Failed to generate Go license report"
        return 1
    }
    
    # Parse and check licenses
    local violations=0
    local reviews=0
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local module_license=$(echo "$line" | cut -d',' -f2 | tr -d '"' | xargs)
            local module_name=$(echo "$line" | cut -d',' -f1 | tr -d '"')
            
            # Skip header line
            if [[ "$module_name" == "Module" ]]; then
                continue
            fi
            
            # Check if license is approved
            local approved=false
            for approved_license in "${APPROVED_LICENSES[@]}"; do
                if [[ "$module_license" == "$approved_license" ]]; then
                    approved=true
                    break
                fi
            done
            
            if [[ "$approved" == true ]]; then
                log_success "✓ $module_name: $module_license"
                continue
            fi
            
            # Check if license requires review
            local needs_review=false
            for review_license in "${REVIEW_REQUIRED[@]}"; do
                if [[ "$module_license" == "$review_license" ]]; then
                    needs_review=true
                    break
                fi
            done
            
            if [[ "$needs_review" == true ]]; then
                log_warning "⚠ $module_name: $module_license (REVIEW REQUIRED)"
                ((reviews++))
                continue
            fi
            
            # Check if license is banned
            local banned=false
            for banned_license in "${BANNED_LICENSES[@]}"; do
                if [[ "$module_license" == "$banned_license" ]]; then
                    banned=true
                    break
                fi
            done
            
            if [[ "$banned" == true ]]; then
                log_error "✗ $module_name: $module_license (BANNED LICENSE)"
                ((violations++))
            else
                log_warning "? $module_name: $module_license (UNKNOWN LICENSE)"
                ((reviews++))
            fi
        fi
    done < "${TEMP_DIR}/go-licenses.json"
    
    if [[ $violations -gt 0 ]]; then
        log_error "Found $violations license violations in Go modules"
        EXIT_CODE=1
    fi
    
    if [[ $reviews -gt 0 ]]; then
        log_warning "Found $reviews licenses requiring manual review in Go modules"
        # Don't fail on reviews, but notify
    fi
}

check_npm_licenses() {
    log_info "Checking NPM package licenses..."
    
    if [[ ! -f "${PROJECT_ROOT}/package.json" ]]; then
        log_info "No package.json found, skipping NPM license check"
        return 0
    fi
    
    cd "${PROJECT_ROOT}"
    
    # Check if license-checker is available
    if ! command -v license-checker &> /dev/null; then
        log_warning "license-checker not found, installing..."
        npm install -g license-checker
    fi
    
    # Generate NPM license report
    license-checker --json --onlyAllow "$(IFS=';'; echo "${APPROVED_LICENSES[*]}")" > "${TEMP_DIR}/npm-licenses.json" 2>/dev/null || {
        log_warning "Some NPM packages have non-approved licenses"
        
        # Get detailed report
        license-checker --json > "${TEMP_DIR}/npm-licenses-full.json"
        
        # Parse and report violations
        local violations=0
        while IFS= read -r line; do
            local package_name=$(echo "$line" | jq -r '.name // empty')
            local license=$(echo "$line" | jq -r '.licenses // empty')
            
            if [[ -n "$package_name" && -n "$license" ]]; then
                # Check if license is banned
                local banned=false
                for banned_license in "${BANNED_LICENSES[@]}"; do
                    if [[ "$license" == "$banned_license" ]]; then
                        banned=true
                        break
                    fi
                done
                
                if [[ "$banned" == true ]]; then
                    log_error "✗ $package_name: $license (BANNED LICENSE)"
                    ((violations++))
                else
                    log_warning "? $package_name: $license (REVIEW REQUIRED)"
                fi
            fi
        done < <(jq -c '.[]' "${TEMP_DIR}/npm-licenses-full.json" 2>/dev/null || echo '{}')
        
        if [[ $violations -gt 0 ]]; then
            log_error "Found $violations license violations in NPM packages"
            EXIT_CODE=1
        fi
    }
}

generate_license_report() {
    log_info "Generating comprehensive license report..."
    
    local report_file="${PROJECT_ROOT}/LICENSE_REPORT.md"
    
    cat > "$report_file" << EOF
# License Report

Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

## Summary

This report contains all third-party licenses used in this project.

## Approved Licenses

The following licenses are pre-approved for use:

EOF
    
    for license in "${APPROVED_LICENSES[@]}"; do
        echo "- $license" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

## Go Module Licenses

EOF
    
    if [[ -f "${TEMP_DIR}/go-licenses.json" ]]; then
        echo "\`\`\`" >> "$report_file"
        cat "${TEMP_DIR}/go-licenses.json" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## NPM Package Licenses

EOF
    
    if [[ -f "${TEMP_DIR}/npm-licenses-full.json" ]]; then
        echo "\`\`\`json" >> "$report_file"
        cat "${TEMP_DIR}/npm-licenses-full.json" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    fi
    
    log_success "License report generated: $report_file"
}

save_license_cache() {
    log_info "Saving license information for future reference..."
    
    local cache_dir="${PROJECT_ROOT}/.licenses"
    mkdir -p "$cache_dir"
    
    # Save Go licenses
    if [[ -f "${TEMP_DIR}/go-licenses.json" ]]; then
        cp "${TEMP_DIR}/go-licenses.json" "$cache_dir/go-licenses.json"
    fi
    
    # Save NPM licenses
    if [[ -f "${TEMP_DIR}/npm-licenses-full.json" ]]; then
        cp "${TEMP_DIR}/npm-licenses-full.json" "$cache_dir/npm-licenses.json"
    fi
    
    # Save approved licenses list
    printf '%s\n' "${APPROVED_LICENSES[@]}" > "$cache_dir/approved-licenses.txt"
    printf '%s\n' "${BANNED_LICENSES[@]}" > "$cache_dir/banned-licenses.txt"
    
    log_success "License cache saved to $cache_dir"
}

main() {
    log_info "Starting license compliance check for Provenance Graph SBOM Linker"
    
    check_go_licenses
    check_npm_licenses
    generate_license_report
    save_license_cache
    
    if [[ $EXIT_CODE -eq 0 ]]; then
        log_success "License compliance check passed"
    else
        log_error "License compliance check failed"
    fi
    
    exit $EXIT_CODE
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi