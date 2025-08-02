#!/bin/bash

# Workflow Automation Script for Provenance Graph SBOM Linker
# =============================================================================
# Automates common development workflow tasks and enforces best practices

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="${PROJECT_ROOT}/.workflow"
TEMPLATES_DIR="${PROJECT_ROOT}/docs/templates"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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
    echo -e "\n${PURPLE}=== $1 ===${NC}\n"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 <command> [options]

Workflow automation for Provenance Graph SBOM Linker development

COMMANDS:
    feature <name>          Create a new feature branch and setup
    bugfix <name>           Create a new bugfix branch and setup
    security <name>         Create a new security fix branch
    release <version>       Prepare a new release
    hotfix <version>        Create an emergency hotfix
    pr create              Create a pull request with template
    pr review              Start code review process
    incident <severity>     Create incident response documentation
    adr <title>            Create new Architecture Decision Record
    checklist release      Generate release checklist
    validate branch        Validate current branch for merge readiness
    setup hooks            Setup git hooks and development tools
    cleanup                Clean up merged branches and temporary files

OPTIONS:
    -h, --help             Show this help message
    -v, --verbose          Enable verbose output
    -n, --dry-run          Show what would be done without executing
    --template <name>      Use specific template
    --priority <level>     Set priority level (low/medium/high/critical)

EXAMPLES:
    $0 feature USER-123-implement-sbom-scanning
    $0 release v1.2.0
    $0 pr create --template security-review
    $0 incident critical
    $0 adr "Implement Zero-Trust Architecture"

EOF
}

# Initialize workflow configuration
init_workflow_config() {
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        mkdir -p "${CONFIG_DIR}"
    fi
    
    # Create default configuration if it doesn't exist
    if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
        cat << EOF > "${CONFIG_DIR}/config.yaml"
# Workflow Configuration
project:
  name: "provenance-graph-sbom-linker"
  repo: "danieleschmidt/provenance-graph-sbom-linker"
  main_branch: "main"
  develop_branch: "develop"

branches:
  feature_prefix: "feature/"
  bugfix_prefix: "bugfix/"
  security_prefix: "security/"
  release_prefix: "release/"
  hotfix_prefix: "hotfix/"

review:
  required_reviewers: 2
  security_review_required: true
  performance_review_threshold: "major"

quality_gates:
  min_test_coverage: 85
  max_complexity: 10
  security_scan_required: true
  license_check_required: true

notifications:
  slack_webhook: ""
  teams_webhook: ""
  email_notifications: true
EOF
    fi
}

# Load configuration
load_config() {
    if [[ -f "${CONFIG_DIR}/config.yaml" ]]; then
        # Simple YAML parsing (assumes basic structure)
        MAIN_BRANCH=$(grep "main_branch:" "${CONFIG_DIR}/config.yaml" | cut -d'"' -f2)
        DEVELOP_BRANCH=$(grep "develop_branch:" "${CONFIG_DIR}/config.yaml" | cut -d'"' -f2)
        MIN_COVERAGE=$(grep "min_test_coverage:" "${CONFIG_DIR}/config.yaml" | awk '{print $2}')
    else
        # Defaults
        MAIN_BRANCH="main"
        DEVELOP_BRANCH="develop"
        MIN_COVERAGE=85
    fi
}

# Validate git repository
validate_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
    
    # Check if we're in the correct repository
    local repo_url=$(git remote get-url origin 2>/dev/null || echo "")
    if [[ ! "$repo_url" =~ provenance-graph-sbom-linker ]]; then
        print_warning "This script is designed for the provenance-graph-sbom-linker repository"
    fi
}

# Setup git hooks
setup_git_hooks() {
    print_section "Setting up Git Hooks"
    
    local hooks_dir="${PROJECT_ROOT}/.git/hooks"
    
    # Pre-commit hook
    cat << 'EOF' > "${hooks_dir}/pre-commit"
#!/bin/bash
# Pre-commit hook for security and quality checks

echo "Running pre-commit checks..."

# Check for secrets
if command -v truffleHog &> /dev/null; then
    echo "Scanning for secrets..."
    if ! truffleHog --regex --entropy=False .; then
        echo "❌ Secrets detected! Please remove them before committing."
        exit 1
    fi
fi

# Run tests
echo "Running tests..."
if ! make test-unit; then
    echo "❌ Unit tests failed! Please fix before committing."
    exit 1
fi

# Check code formatting
echo "Checking code formatting..."
if ! make format-check; then
    echo "❌ Code formatting issues found! Run 'make format' to fix."
    exit 1
fi

# Security scan
echo "Running security scan..."
if ! make security-scan; then
    echo "❌ Security issues found! Please review and fix."
    exit 1
fi

echo "✅ All pre-commit checks passed!"
EOF

    # Commit message hook
    cat << 'EOF' > "${hooks_dir}/commit-msg"
#!/bin/bash
# Commit message validation hook

commit_regex='^(feat|fix|docs|style|refactor|test|chore|security|perf|build|ci|revert)(\(.+\))?: .{1,50}'

if ! grep -qE "$commit_regex" "$1"; then
    echo "❌ Invalid commit message format!"
    echo "Format: <type>[optional scope]: <description>"
    echo "Types: feat, fix, docs, style, refactor, test, chore, security, perf, build, ci, revert"
    echo "Example: feat(auth): add multi-factor authentication"
    exit 1
fi

echo "✅ Commit message format is valid"
EOF

    # Make hooks executable
    chmod +x "${hooks_dir}/pre-commit"
    chmod +x "${hooks_dir}/commit-msg"
    
    print_success "Git hooks installed successfully"
}

# Create feature branch
create_feature_branch() {
    local feature_name="$1"
    if [[ -z "$feature_name" ]]; then
        print_error "Feature name is required"
        exit 1
    fi
    
    print_section "Creating Feature Branch"
    
    # Ensure we're on develop branch
    git checkout "${DEVELOP_BRANCH}"
    git pull origin "${DEVELOP_BRANCH}"
    
    # Create feature branch
    local branch_name="feature/${feature_name}"
    git checkout -b "${branch_name}"
    
    # Create feature documentation
    local feature_doc="${PROJECT_ROOT}/docs/features/${feature_name}.md"
    mkdir -p "$(dirname "${feature_doc}")"
    
    cat << EOF > "${feature_doc}"
# Feature: ${feature_name}

## Overview
[Brief description of the feature]

## Requirements
- [ ] Requirement 1
- [ ] Requirement 2
- [ ] Requirement 3

## Implementation Plan
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Testing Strategy
- [ ] Unit tests
- [ ] Integration tests
- [ ] Security tests
- [ ] Performance tests

## Acceptance Criteria
- [ ] Criteria 1
- [ ] Criteria 2
- [ ] Criteria 3

## Security Considerations
[Security aspects to consider]

## Performance Impact
[Expected performance impact]

## Documentation Updates
- [ ] API documentation
- [ ] User documentation
- [ ] Developer documentation
EOF
    
    git add "${feature_doc}"
    git commit -m "docs: create feature documentation for ${feature_name}"
    
    print_success "Feature branch '${branch_name}' created successfully"
    print_info "Feature documentation created at: ${feature_doc}"
}

# Create security fix branch
create_security_branch() {
    local security_name="$1"
    if [[ -z "$security_name" ]]; then
        print_error "Security fix name is required"
        exit 1
    fi
    
    print_section "Creating Security Fix Branch"
    
    # Create security branch from main for urgent fixes
    git checkout "${MAIN_BRANCH}"
    git pull origin "${MAIN_BRANCH}"
    
    local branch_name="security/${security_name}"
    git checkout -b "${branch_name}"
    
    # Create security documentation
    local security_doc="${PROJECT_ROOT}/docs/security/${security_name}.md"
    mkdir -p "$(dirname "${security_doc}")"
    
    cat << EOF > "${security_doc}"
# Security Fix: ${security_name}

## Security Issue
**Severity:** [Critical/High/Medium/Low]
**CVE ID:** [If applicable]
**Discovery Date:** $(date -u +"%Y-%m-%d")

## Description
[Detailed description of the security issue]

## Impact Assessment
- **Confidentiality:** [High/Medium/Low/None]
- **Integrity:** [High/Medium/Low/None]
- **Availability:** [High/Medium/Low/None]

## Affected Systems
- [ ] System 1
- [ ] System 2
- [ ] System 3

## Fix Implementation
[Description of the fix]

## Testing
- [ ] Security test cases created
- [ ] Regression tests passed
- [ ] Penetration testing completed

## Verification
- [ ] Fix verified in development
- [ ] Fix verified in staging
- [ ] Security scan passed

## Deployment Plan
[Special deployment considerations]

## Communication Plan
- [ ] Security team notified
- [ ] Stakeholders informed
- [ ] Customers notified (if needed)
EOF
    
    git add "${security_doc}"
    git commit -m "security: create documentation for ${security_name}"
    
    print_success "Security branch '${branch_name}' created successfully"
    print_warning "Remember to follow security review process before merging"
}

# Prepare release
prepare_release() {
    local version="$1"
    if [[ -z "$version" ]]; then
        print_error "Version number is required (e.g., v1.2.0)"
        exit 1
    fi
    
    print_section "Preparing Release ${version}"
    
    # Create release branch from develop
    git checkout "${DEVELOP_BRANCH}"
    git pull origin "${DEVELOP_BRANCH}"
    
    local branch_name="release/${version}"
    git checkout -b "${branch_name}"
    
    # Generate release checklist
    local checklist_file="${PROJECT_ROOT}/release-${version}-checklist.md"
    cp "${TEMPLATES_DIR}/RELEASE_CHECKLIST_TEMPLATE.md" "${checklist_file}"
    
    # Update version placeholders
    sed -i.bak "s/\[e\.g\., v1\.2\.0\]/${version}/g" "${checklist_file}"
    sed -i.bak "s/\[YYYY-MM-DD\]/$(date +%Y-%m-%d)/g" "${checklist_file}"
    rm "${checklist_file}.bak" 2>/dev/null || true
    
    # Update version in code files (if applicable)
    if [[ -f "${PROJECT_ROOT}/VERSION" ]]; then
        echo "${version#v}" > "${PROJECT_ROOT}/VERSION"
        git add "${PROJECT_ROOT}/VERSION"
    fi
    
    git add "${checklist_file}"
    git commit -m "release: prepare ${version} release checklist"
    
    print_success "Release branch '${branch_name}' created successfully"
    print_info "Release checklist: ${checklist_file}"
    print_info "Complete the checklist before merging to main"
}

# Create pull request
create_pull_request() {
    local template_type="${1:-default}"
    
    print_section "Creating Pull Request"
    
    local current_branch=$(git branch --show-current)
    local pr_title=$(git log --oneline -1 --pretty=format:"%s")
    
    # Determine PR template based on branch type
    if [[ "$current_branch" =~ ^security/ ]]; then
        template_type="security"
    elif [[ "$current_branch" =~ ^release/ ]]; then
        template_type="release"
    elif [[ "$current_branch" =~ ^hotfix/ ]]; then
        template_type="hotfix"
    fi
    
    # Create PR description
    local pr_body_file="/tmp/pr-body-$$.md"
    
    case "$template_type" in
        security)
            cat << EOF > "$pr_body_file"
## Security Fix

**Security Issue:** [Brief description]
**Severity:** [Critical/High/Medium/Low]
**CVE ID:** [If applicable]

### Changes Made
- [ ] Change 1
- [ ] Change 2

### Security Review
- [ ] Security team review completed
- [ ] Penetration testing performed
- [ ] Vulnerability scan passed

### Testing
- [ ] Unit tests updated
- [ ] Security tests added
- [ ] Integration tests passed

### Deployment Considerations
[Any special deployment notes]

### Verification Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]
EOF
            ;;
        release)
            cat << EOF > "$pr_body_file"
## Release: ${current_branch#release/}

### Release Summary
[Brief description of the release]

### Features Included
- [ ] Feature 1
- [ ] Feature 2

### Bug Fixes
- [ ] Fix 1
- [ ] Fix 2

### Release Checklist Completed
- [ ] All tests passing
- [ ] Security scan completed
- [ ] Performance benchmarks met
- [ ] Documentation updated

### Breaking Changes
- [ ] No breaking changes
- [ ] Breaking changes documented below

### Deployment Plan
[Deployment strategy and timeline]
EOF
            ;;
        *)
            cat << EOF > "$pr_body_file"
## Changes

### Description
[Describe the changes made in this PR]

### Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

### Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests passing
- [ ] Manual testing completed

### Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Code is properly commented
- [ ] Documentation updated
- [ ] No new warnings introduced
EOF
            ;;
    esac
    
    # Use GitHub CLI if available
    if command -v gh &> /dev/null; then
        gh pr create --title "$pr_title" --body-file "$pr_body_file"
        print_success "Pull request created successfully"
    else
        print_info "GitHub CLI not found. Use the following template for your PR:"
        cat "$pr_body_file"
    fi
    
    rm -f "$pr_body_file"
}

# Create incident documentation
create_incident_documentation() {
    local severity="${1:-medium}"
    
    print_section "Creating Incident Documentation"
    
    local incident_id="INC-$(date +%Y-%m%d)-$(openssl rand -hex 2 | tr '[:lower:]' '[:upper:]')"
    local incident_file="${PROJECT_ROOT}/incidents/${incident_id}.md"
    mkdir -p "$(dirname "${incident_file}")"
    
    # Copy template and customize
    cp "${TEMPLATES_DIR}/INCIDENT_RESPONSE_TEMPLATE.md" "${incident_file}"
    
    # Update placeholders
    sed -i.bak "s/\[INC-YYYY-MMDD-XXX\]/${incident_id}/g" "${incident_file}"
    sed -i.bak "s/\[YYYY-MM-DD HH:MM UTC\]/$(date -u '+%Y-%m-%d %H:%M UTC')/g" "${incident_file}"
    sed -i.bak "s/\[P0\/P1\/P2\/P3\]/P${severity}/g" "${incident_file}"
    rm "${incident_file}.bak" 2>/dev/null || true
    
    print_success "Incident documentation created: ${incident_file}"
    print_info "Incident ID: ${incident_id}"
    
    # Open in editor if available
    if command -v code &> /dev/null; then
        code "${incident_file}"
    elif [[ -n "$EDITOR" ]]; then
        "$EDITOR" "${incident_file}"
    fi
}

# Create Architecture Decision Record
create_adr() {
    local title="$1"
    if [[ -z "$title" ]]; then
        print_error "ADR title is required"
        exit 1
    fi
    
    print_section "Creating Architecture Decision Record"
    
    # Find next ADR number
    local adr_dir="${PROJECT_ROOT}/docs/adr"
    mkdir -p "${adr_dir}"
    
    local next_num=1
    if [[ -d "$adr_dir" ]]; then
        local max_num=$(find "$adr_dir" -name "ADR-*.md" | sed 's/.*ADR-\([0-9]*\).*/\1/' | sort -n | tail -1)
        if [[ -n "$max_num" ]]; then
            next_num=$((max_num + 1))
        fi
    fi
    
    local adr_num=$(printf "%04d" $next_num)
    local adr_filename="ADR-${adr_num}-$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g').md"
    local adr_file="${adr_dir}/${adr_filename}"
    
    # Copy template and customize
    cp "${TEMPLATES_DIR}/ARCHITECTURE_DECISION_RECORD_TEMPLATE.md" "${adr_file}"
    
    # Update placeholders
    sed -i.bak "s/\[ADR-XXXX\]/ADR-${adr_num}/g" "${adr_file}"
    sed -i.bak "s/\[Decision Title\]/${title}/g" "${adr_file}"
    sed -i.bak "s/\[YYYY-MM-DD\]/$(date +%Y-%m-%d)/g" "${adr_file}"
    sed -i.bak "s/\[Proposed\/Accepted\/Superseded\/Deprecated\]/Proposed/g" "${adr_file}"
    rm "${adr_file}.bak" 2>/dev/null || true
    
    print_success "ADR created: ${adr_file}"
    print_info "ADR Number: ADR-${adr_num}"
    
    # Open in editor if available
    if command -v code &> /dev/null; then
        code "${adr_file}"
    elif [[ -n "$EDITOR" ]]; then
        "$EDITOR" "${adr_file}"
    fi
}

# Validate branch for merge readiness
validate_branch() {
    print_section "Validating Branch for Merge Readiness"
    
    local current_branch=$(git branch --show-current)
    local validation_passed=true
    
    print_info "Validating branch: ${current_branch}"
    
    # Check if branch is up to date
    print_info "Checking if branch is up to date..."
    git fetch origin
    local behind_count=$(git rev-list --count "${current_branch}..origin/${DEVELOP_BRANCH}")
    if [[ $behind_count -gt 0 ]]; then
        print_warning "Branch is ${behind_count} commits behind ${DEVELOP_BRANCH}"
        validation_passed=false
    else
        print_success "Branch is up to date"
    fi
    
    # Run tests
    print_info "Running tests..."
    if make test &> /dev/null; then
        print_success "All tests passing"
    else
        print_error "Tests are failing"
        validation_passed=false
    fi
    
    # Check test coverage
    print_info "Checking test coverage..."
    local coverage=$(make test-coverage 2>/dev/null | grep "total:" | awk '{print $3}' | sed 's/%//')
    if [[ -n "$coverage" ]] && [[ $(echo "$coverage >= $MIN_COVERAGE" | bc -l) -eq 1 ]]; then
        print_success "Test coverage: ${coverage}% (>= ${MIN_COVERAGE}%)"
    else
        print_error "Test coverage below minimum: ${coverage}% (required: ${MIN_COVERAGE}%)"
        validation_passed=false
    fi
    
    # Security scan
    print_info "Running security scan..."
    if make security-scan &> /dev/null; then
        print_success "Security scan passed"
    else
        print_error "Security scan failed"
        validation_passed=false
    fi
    
    # Check for merge conflicts
    print_info "Checking for merge conflicts..."
    if git merge-tree "$(git merge-base HEAD origin/${DEVELOP_BRANCH})" HEAD "origin/${DEVELOP_BRANCH}" | grep -q "<<<<<<< "; then
        print_error "Merge conflicts detected"
        validation_passed=false
    else
        print_success "No merge conflicts"
    fi
    
    # Final result
    if [[ "$validation_passed" == "true" ]]; then
        print_success "✅ Branch validation passed - ready for merge!"
    else
        print_error "❌ Branch validation failed - please address issues before merging"
        exit 1
    fi
}

# Cleanup merged branches
cleanup_branches() {
    print_section "Cleaning Up Merged Branches"
    
    # Fetch latest changes
    git fetch origin --prune
    
    # Find merged branches
    local merged_branches=$(git branch --merged "${MAIN_BRANCH}" | grep -v "${MAIN_BRANCH}" | grep -v "${DEVELOP_BRANCH}" | grep -v "^\*")
    
    if [[ -n "$merged_branches" ]]; then
        print_info "Found merged branches to clean up:"
        echo "$merged_branches"
        
        if [[ "${DRY_RUN}" != "true" ]]; then
            read -p "Delete these branches? (y/N): " -r
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "$merged_branches" | xargs -n1 git branch -d
                print_success "Merged branches deleted"
            fi
        else
            print_info "[DRY RUN] Would delete merged branches"
        fi
    else
        print_info "No merged branches to clean up"
    fi
    
    # Clean up temporary files
    find "${PROJECT_ROOT}" -name "*.tmp" -delete 2>/dev/null || true
    find "${PROJECT_ROOT}" -name ".DS_Store" -delete 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Main function
main() {
    local command="$1"
    shift
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --template)
                TEMPLATE="$2"
                shift 2
                ;;
            --priority)
                PRIORITY="$2"
                shift 2
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Initialize and validate
    init_workflow_config
    load_config
    validate_git_repo
    
    # Execute command
    case "$command" in
        feature)
            create_feature_branch "$1"
            ;;
        bugfix)
            create_feature_branch "$1"  # Same process as feature
            ;;
        security)
            create_security_branch "$1"
            ;;
        release)
            prepare_release "$1"
            ;;
        hotfix)
            # Similar to security but for urgent production fixes
            create_security_branch "$1"
            ;;
        pr)
            case "$1" in
                create)
                    create_pull_request "${TEMPLATE:-default}"
                    ;;
                review)
                    print_info "Starting code review process..."
                    # Could integrate with GitHub/GitLab APIs
                    ;;
                *)
                    print_error "Unknown pr subcommand: $1"
                    exit 1
                    ;;
            esac
            ;;
        incident)
            create_incident_documentation "$1"
            ;;
        adr)
            create_adr "$*"
            ;;
        checklist)
            case "$1" in
                release)
                    print_info "Use: $0 release <version> to generate release checklist"
                    ;;
                *)
                    print_error "Unknown checklist type: $1"
                    exit 1
                    ;;
            esac
            ;;
        validate)
            case "$1" in
                branch)
                    validate_branch
                    ;;
                *)
                    print_error "Unknown validate subcommand: $1"
                    exit 1
                    ;;
            esac
            ;;
        setup)
            case "$1" in
                hooks)
                    setup_git_hooks
                    ;;
                *)
                    print_error "Unknown setup subcommand: $1"
                    exit 1
                    ;;
            esac
            ;;
        cleanup)
            cleanup_branches
            ;;
        *)
            print_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"