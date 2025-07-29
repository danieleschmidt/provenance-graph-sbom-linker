#!/bin/bash
# =============================================================================
# SBOM Validation Script for Provenance Graph SBOM Linker
# =============================================================================
# Validates SBOM files for format compliance and content accuracy

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VALIDATION_LOG="${ROOT_DIR}/logs/sbom-validation.log"

# Ensure logs directory exists
mkdir -p "${ROOT_DIR}/logs"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "${VALIDATION_LOG}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "${VALIDATION_LOG}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "${VALIDATION_LOG}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "${VALIDATION_LOG}"
}

# Function to validate CycloneDX SBOM
validate_cyclonedx() {
    local sbom_file="$1"
    
    log "Validating CycloneDX SBOM: ${sbom_file}"
    
    # Check if file exists
    if [[ ! -f "$sbom_file" ]]; then
        log_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    # Check JSON syntax
    if ! jq empty "$sbom_file" 2>/dev/null; then
        log_error "Invalid JSON syntax in: $sbom_file"
        return 1
    fi
    
    # Validate CycloneDX schema version
    local schema_version
    schema_version=$(jq -r '.specVersion // "unknown"' "$sbom_file")
    
    if [[ "$schema_version" == "unknown" ]]; then
        log_error "Missing specVersion in CycloneDX SBOM"
        return 1
    fi
    
    log "CycloneDX schema version: $schema_version"
    
    # Validate required fields
    local required_fields=("bomFormat" "specVersion" "serialNumber" "version" "metadata")
    local missing_fields=()
    
    for field in "${required_fields[@]}"; do
        if ! jq -e ".$field" "$sbom_file" >/dev/null 2>&1; then
            missing_fields+=("$field")
        fi
    done
    
    if [[ ${#missing_fields[@]} -gt 0 ]]; then
        log_error "Missing required fields in CycloneDX SBOM: ${missing_fields[*]}"
        return 1
    fi
    
    # Validate components array
    local component_count
    component_count=$(jq '.components | length' "$sbom_file")
    
    if [[ "$component_count" -eq 0 ]]; then
        log_warning "No components found in SBOM"
    else
        log "Found $component_count components in SBOM"
    fi
    
    # Validate component structure
    local invalid_components
    invalid_components=$(jq '[.components[]? | select(.name == null or .version == null or .type == null)] | length' "$sbom_file")
    
    if [[ "$invalid_components" -gt 0 ]]; then
        log_error "Found $invalid_components components with missing required fields (name, version, type)"
        return 1
    fi
    
    # Check for vulnerabilities
    local vuln_count
    vuln_count=$(jq '.vulnerabilities | length // 0' "$sbom_file")
    
    if [[ "$vuln_count" -gt 0 ]]; then
        log_warning "Found $vuln_count vulnerabilities in SBOM"
        
        # Count critical vulnerabilities
        local critical_vulns
        critical_vulns=$(jq '[.vulnerabilities[]? | select(.ratings[]?.severity == "critical")] | length' "$sbom_file")
        
        if [[ "$critical_vulns" -gt 0 ]]; then
            log_error "Found $critical_vulns critical vulnerabilities - this may block deployment"
        fi
    fi
    
    log_success "CycloneDX SBOM validation passed: $sbom_file"
    return 0
}

# Function to validate SPDX SBOM
validate_spdx() {
    local sbom_file="$1"
    
    log "Validating SPDX SBOM: ${sbom_file}"
    
    # Check if file exists
    if [[ ! -f "$sbom_file" ]]; then
        log_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    # Check JSON syntax
    if ! jq empty "$sbom_file" 2>/dev/null; then
        log_error "Invalid JSON syntax in: $sbom_file"
        return 1
    fi
    
    # Validate SPDX version
    local spdx_version
    spdx_version=$(jq -r '.spdxVersion // "unknown"' "$sbom_file")
    
    if [[ "$spdx_version" == "unknown" ]]; then
        log_error "Missing spdxVersion in SPDX SBOM"
        return 1
    fi
    
    log "SPDX version: $spdx_version"
    
    # Validate required fields
    local required_fields=("SPDXID" "spdxVersion" "creationInfo" "name" "dataLicense")
    local missing_fields=()
    
    for field in "${required_fields[@]}"; do
        if ! jq -e ".$field" "$sbom_file" >/dev/null 2>&1; then
            missing_fields+=("$field")
        fi
    done
    
    if [[ ${#missing_fields[@]} -gt 0 ]]; then
        log_error "Missing required fields in SPDX SBOM: ${missing_fields[*]}"
        return 1
    fi
    
    # Validate packages array
    local package_count
    package_count=$(jq '.packages | length // 0' "$sbom_file")
    
    if [[ "$package_count" -eq 0 ]]; then
        log_warning "No packages found in SBOM"
    else
        log "Found $package_count packages in SBOM"
    fi
    
    # Validate package structure
    local invalid_packages
    invalid_packages=$(jq '[.packages[]? | select(.name == null or .SPDXID == null)] | length' "$sbom_file")
    
    if [[ "$invalid_packages" -gt 0 ]]; then
        log_error "Found $invalid_packages packages with missing required fields (name, SPDXID)"
        return 1
    fi
    
    log_success "SPDX SBOM validation passed: $sbom_file"
    return 0
}

# Function to validate SBOM completeness
validate_completeness() {
    local sbom_file="$1"
    local sbom_format="$2"
    
    log "Validating SBOM completeness: ${sbom_file}"
    
    case "$sbom_format" in
        "cyclonedx")
            # Check for supplier information
            local suppliers_missing
            suppliers_missing=$(jq '[.components[]? | select(.supplier == null)] | length' "$sbom_file")
            
            if [[ "$suppliers_missing" -gt 0 ]]; then
                log_warning "$suppliers_missing components missing supplier information"
            fi
            
            # Check for license information
            local licenses_missing
            licenses_missing=$(jq '[.components[]? | select(.licenses == null or (.licenses | length) == 0)] | length' "$sbom_file")
            
            if [[ "$licenses_missing" -gt 0 ]]; then
                log_warning "$licenses_missing components missing license information"
            fi
            
            # Check for hash/checksum information
            local hashes_missing
            hashes_missing=$(jq '[.components[]? | select(.hashes == null or (.hashes | length) == 0)] | length' "$sbom_file")
            
            if [[ "$hashes_missing" -gt 0 ]]; then
                log_warning "$hashes_missing components missing hash information"
            fi
            ;;
            
        "spdx")
            # Check for license information
            local packages_no_license
            packages_no_license=$(jq '[.packages[]? | select(.licenseConcluded == null and .licenseDeclared == null)] | length' "$sbom_file")
            
            if [[ "$packages_no_license" -gt 0 ]]; then
                log_warning "$packages_no_license packages missing license information"
            fi
            
            # Check for copyright information
            local copyright_missing
            copyright_missing=$(jq '[.packages[]? | select(.copyrightText == null)] | length' "$sbom_file")
            
            if [[ "$copyright_missing" -gt 0 ]]; then
                log_warning "$copyright_missing packages missing copyright information"
            fi
            ;;
    esac
    
    log_success "SBOM completeness validation completed"
}

# Function to validate SBOM signatures
validate_signatures() {
    local sbom_file="$1"
    
    log "Validating SBOM signatures: ${sbom_file}"
    
    # Check for signature file
    local sig_file="${sbom_file}.sig"
    
    if [[ -f "$sig_file" ]]; then
        log "Found signature file: $sig_file"
        
        # Validate signature using cosign (if available)
        if command -v cosign >/dev/null 2>&1; then
            if cosign verify-blob --signature="$sig_file" "$sbom_file" 2>/dev/null; then
                log_success "SBOM signature validation passed"
            else
                log_warning "SBOM signature validation failed or no public key available"
            fi
        else
            log_warning "cosign not available for signature validation"
        fi
    else
        log_warning "No signature file found for SBOM: $sbom_file"
    fi
}

# Main validation function
validate_sbom() {
    local sbom_file="$1"
    local validation_errors=0
    
    log "Starting SBOM validation for: $sbom_file"
    
    # Detect SBOM format
    local sbom_format="unknown"
    
    if jq -e '.bomFormat' "$sbom_file" >/dev/null 2>&1; then
        sbom_format="cyclonedx"
    elif jq -e '.spdxVersion' "$sbom_file" >/dev/null 2>&1; then
        sbom_format="spdx"
    fi
    
    log "Detected SBOM format: $sbom_format"
    
    # Validate based on format
    case "$sbom_format" in
        "cyclonedx")
            if ! validate_cyclonedx "$sbom_file"; then
                ((validation_errors++))
            fi
            ;;
        "spdx")
            if ! validate_spdx "$sbom_file"; then
                ((validation_errors++))
            fi
            ;;
        *)
            log_error "Unknown or unsupported SBOM format"
            ((validation_errors++))
            ;;
    esac
    
    # Validate completeness
    if [[ "$sbom_format" != "unknown" ]]; then
        validate_completeness "$sbom_file" "$sbom_format"
    fi
    
    # Validate signatures
    validate_signatures "$sbom_file"
    
    return $validation_errors
}

# Help function
show_help() {
    cat << EOF
SBOM Validation Script

Usage: $0 [OPTIONS] <sbom-file>

Options:
    -h, --help          Show this help message
    -f, --format FORMAT Specify SBOM format (cyclonedx, spdx, auto)
    -s, --strict        Enable strict validation mode
    -q, --quiet         Suppress non-error output
    
Examples:
    $0 sbom.cyclonedx.json
    $0 --format spdx sbom.spdx.json
    $0 --strict --quiet sbom.json

Exit codes:
    0: Validation passed
    1: Validation failed
    2: Invalid arguments
EOF
}

# Parse command line arguments
STRICT_MODE=false
QUIET_MODE=false
FORMAT="auto"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -s|--strict)
            STRICT_MODE=true
            shift
            ;;
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            exit 2
            ;;
        *)
            SBOM_FILE="$1"
            shift
            ;;
    esac
done

# Check if SBOM file is provided
if [[ -z "${SBOM_FILE:-}" ]]; then
    log_error "SBOM file not specified"
    show_help
    exit 2
fi

# Main execution
log "SBOM Validation Script started"
log "Configuration: FORMAT=$FORMAT, STRICT_MODE=$STRICT_MODE, QUIET_MODE=$QUIET_MODE"

if validate_sbom "$SBOM_FILE"; then
    log_success "All SBOM validations passed for: $SBOM_FILE"
    exit 0
else
    log_error "SBOM validation failed for: $SBOM_FILE"
    exit 1
fi