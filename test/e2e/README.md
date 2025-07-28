# End-to-End Tests

This directory contains end-to-end (E2E) tests for the Provenance Graph SBOM Linker.

## Overview

End-to-end tests validate complete user workflows and system behavior from the user's perspective. They test the entire system including UI, API, database, and external integrations.

## Structure

```
e2e/
├── README.md                    # This file
├── api/                        # API E2E tests
│   ├── provenance_flow_test.go # Complete provenance workflows
│   ├── compliance_test.go      # Compliance reporting flows
│   └── security_test.go        # Security workflow tests
├── cli/                        # CLI E2E tests
│   ├── init_test.go           # Project initialization
│   ├── track_test.go          # Artifact tracking
│   └── verify_test.go         # Verification workflows
├── web/                        # Web UI E2E tests
│   ├── dashboard_test.go       # Dashboard functionality
│   ├── visualization_test.go   # Graph visualization
│   └── reports_test.go         # Report generation
├── scenarios/                  # Business scenario tests
│   ├── cicd_integration_test.go # CI/CD pipeline integration
│   ├── vulnerability_response_test.go # Vulnerability response
│   └── audit_trail_test.go     # Audit and compliance
├── fixtures/                   # Test data and artifacts
│   ├── sample_repo/           # Sample Git repository
│   ├── test_artifacts/        # Test container images, binaries
│   └── policies/              # Test security policies
└── helpers/                    # Test helper utilities
    ├── test_environment.go    # Environment setup
    ├── api_client.go          # Test API client
    └── assertions.go          # Custom assertions
```

## Test Environment

E2E tests require a complete test environment with all services running.

### Prerequisites

```bash
# Start complete test environment
make e2e-setup

# This starts:
# - API server
# - Web dashboard
# - Neo4j database
# - Redis cache
# - MinIO object storage
# - Test external services (mocked)
```

### Environment Configuration

```yaml
# e2e-config.yaml
environment:
  type: e2e
  cleanup: true
  
services:
  api:
    url: http://localhost:8080
    timeout: 30s
  
  web:
    url: http://localhost:3000
    browser: chrome
    headless: true
  
  database:
    neo4j_uri: bolt://localhost:7687
    redis_url: redis://localhost:6379
  
mocks:
  github_api: true
  container_registry: true
  vulnerability_scanner: true
  
test_data:
  cleanup_after: true
  preserve_on_failure: false
```

## Running E2E Tests

```bash
# All E2E tests
make test-e2e

# Specific test suite
go test -tags=e2e ./test/e2e/scenarios/

# With verbose output
go test -tags=e2e -v ./test/e2e/...

# Single test
go test -tags=e2e -run TestCompleteWorkflow ./test/e2e/scenarios/

# With browser visible (for web tests)
HEADLESS=false make test-e2e
```

## Test Structure

### Test Setup and Teardown

```go
//go:build e2e
// +build e2e

package e2e

import (
    "testing"
    "context"
    "time"
)

var (
    testEnv *TestEnvironment
)

func TestMain(m *testing.M) {
    // Setup complete test environment
    var err error
    testEnv, err = SetupE2EEnvironment()
    if err != nil {
        log.Fatal("Failed to setup E2E environment:", err)
    }
    
    // Run tests
    code := m.Run()
    
    // Cleanup
    testEnv.Cleanup()
    os.Exit(code)
}
```

### Test Example

```go
func TestCompleteProvenanceWorkflow(t *testing.T) {
    ctx := context.Background()
    
    // Step 1: Initialize project
    t.Run("initialize_project", func(t *testing.T) {
        cmd := exec.Command("provenance-linker", "init", "--project", "e2e-test-app")
        output, err := cmd.CombinedOutput()
        assert.NoError(t, err, "Command output: %s", output)
        
        // Verify .provenance.yaml was created
        assert.FileExists(t, ".provenance.yaml")
    })
    
    // Step 2: Track a build
    t.Run("track_build", func(t *testing.T) {
        buildEvent := &types.BuildEvent{
            SourceRef:  "git@github.com:e2e/test-repo.git@main",
            CommitHash: "abc123def456",
            Artifacts: []types.Artifact{
                {
                    Name:    "e2e-test-app",
                    Version: "v1.0.0",
                    Type:    "container",
                    Hash:    "sha256:fedcba654321",
                },
            },
        }
        
        client := testEnv.APIClient()
        err := client.TrackBuild(ctx, buildEvent)
        assert.NoError(t, err)
    })
    
    // Step 3: Generate SBOM
    t.Run("generate_sbom", func(t *testing.T) {
        cmd := exec.Command("provenance-linker", "sbom", "generate",
            "--source", "./test/fixtures/sample_app",
            "--format", "cyclonedx",
            "--output", "test-sbom.json")
        
        err := cmd.Run()
        assert.NoError(t, err)
        assert.FileExists(t, "test-sbom.json")
    })
    
    // Step 4: Sign artifact
    t.Run("sign_artifact", func(t *testing.T) {
        cmd := exec.Command("provenance-linker", "sign",
            "--artifact", "e2e-test-app:v1.0.0",
            "--key", "test/fixtures/cosign.key")
        
        err := cmd.Run()
        assert.NoError(t, err)
    })
    
    // Step 5: Verify complete provenance
    t.Run("verify_provenance", func(t *testing.T) {
        client := testEnv.APIClient()
        provenance, err := client.GetProvenance(ctx, "e2e-test-app:v1.0.0")
        
        assert.NoError(t, err)
        assert.Equal(t, "abc123def456", provenance.SourceCommit)
        assert.NotNil(t, provenance.SBOM)
        assert.NotNil(t, provenance.Signature)
        assert.True(t, provenance.Verified)
    })
    
    // Step 6: Generate compliance report
    t.Run("compliance_report", func(t *testing.T) {
        cmd := exec.Command("provenance-linker", "compliance", "nist-ssdf",
            "--project", "e2e-test-app",
            "--output", "compliance-report.pdf")
        
        err := cmd.Run()
        assert.NoError(t, err)
        assert.FileExists(t, "compliance-report.pdf")
    })
}
```

## CLI Testing

### Command Testing Framework

```go
type CLITest struct {
    name     string
    args     []string
    input    string
    want     CLIResult
    wantErr  bool
    setup    func() error
    cleanup  func() error
}

type CLIResult struct {
    exitCode int
    stdout   string
    stderr   string
    files    []string
}

func RunCLITests(t *testing.T, tests []CLITest) {
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if tt.setup != nil {
                err := tt.setup()
                require.NoError(t, err)
            }
            
            if tt.cleanup != nil {
                defer tt.cleanup()
            }
            
            result := runCLICommand(tt.args, tt.input)
            
            if tt.wantErr {
                assert.NotEqual(t, 0, result.exitCode)
            } else {
                assert.Equal(t, 0, result.exitCode)
                assert.Contains(t, result.stdout, tt.want.stdout)
            }
            
            for _, file := range tt.want.files {
                assert.FileExists(t, file)
            }
        })
    }
}
```

### CLI Test Examples

```go
func TestCLI_InitCommand(t *testing.T) {
    tests := []CLITest{
        {
            name: "successful_init",
            args: []string{"init", "--project", "test-project"},
            want: CLIResult{
                stdout: "Project initialized successfully",
                files:  []string{".provenance.yaml"},
            },
            wantErr: false,
        },
        {
            name: "init_existing_project",
            args: []string{"init", "--project", "test-project"},
            setup: func() error {
                return createFile(".provenance.yaml", "existing: true")
            },
            cleanup: func() error {
                return os.Remove(".provenance.yaml")
            },
            wantErr: true,
        },
    }
    
    RunCLITests(t, tests)
}
```

## Web UI Testing

### Browser Testing Setup

```go
import (
    "github.com/chromedp/chromedp"
    "github.com/chromedp/cdproto/cdp"
)

func TestWebDashboard(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping web UI tests in short mode")
    }
    
    // Setup browser context
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()
    
    // Set timeout
    ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
    defer cancel()
    
    // Test dashboard loading
    var title string
    err := chromedp.Run(ctx,
        chromedp.Navigate("http://localhost:3000"),
        chromedp.WaitVisible("#dashboard", chromedp.ByID),
        chromedp.Title(&title),
    )
    
    assert.NoError(t, err)
    assert.Contains(t, title, "Provenance Dashboard")
}
```

### Web UI Test Examples

```go
func TestWebUI_ProvenanceVisualization(t *testing.T) {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()
    
    ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
    defer cancel()
    
    // Navigate to provenance page
    var nodes []*cdp.Node
    err := chromedp.Run(ctx,
        chromedp.Navigate("http://localhost:3000/provenance/test-app:v1.0.0"),
        chromedp.WaitVisible("#provenance-graph", chromedp.ByID),
        chromedp.Nodes(".graph-node", &nodes, chromedp.ByQueryAll),
    )
    
    assert.NoError(t, err)
    assert.True(t, len(nodes) > 0, "Expected graph nodes to be present")
    
    // Test graph interactions
    err = chromedp.Run(ctx,
        chromedp.Click(".graph-node[data-type='commit']", chromedp.ByQuery),
        chromedp.WaitVisible("#node-details", chromedp.ByID),
    )
    
    assert.NoError(t, err)
}
```

## Scenario Tests

### CI/CD Integration Scenario

```go
func TestCICDIntegrationScenario(t *testing.T) {
    scenario := NewE2EScenario(t, "cicd-integration")
    defer scenario.Cleanup()
    
    // Step 1: Setup mock CI/CD environment
    t.Run("setup_cicd", func(t *testing.T) {
        err := scenario.SetupMockCI()
        assert.NoError(t, err)
    })
    
    // Step 2: Trigger build via webhook
    t.Run("trigger_build", func(t *testing.T) {
        webhook := &github.WebhookPayload{
            Repository: "test/app",
            Ref:        "refs/heads/main",
            HeadCommit: "abc123",
        }
        
        err := scenario.SendGitHubWebhook(webhook)
        assert.NoError(t, err)
    })
    
    // Step 3: Wait for build completion
    t.Run("wait_for_build", func(t *testing.T) {
        build, err := scenario.WaitForBuildCompletion("abc123", 5*time.Minute)
        assert.NoError(t, err)
        assert.Equal(t, "success", build.Status)
    })
    
    // Step 4: Verify provenance was recorded
    t.Run("verify_provenance", func(t *testing.T) {
        client := scenario.APIClient()
        provenance, err := client.GetProvenance(context.Background(), "test/app:abc123")
        
        assert.NoError(t, err)
        assert.Equal(t, "abc123", provenance.SourceCommit)
        assert.NotNil(t, provenance.BuildInfo)
        assert.True(t, provenance.Verified)
    })
}
```

### Vulnerability Response Scenario

```go
func TestVulnerabilityResponseScenario(t *testing.T) {
    scenario := NewE2EScenario(t, "vuln-response")
    defer scenario.Cleanup()
    
    // Step 1: Setup artifacts with known vulnerability
    t.Run("setup_vulnerable_artifact", func(t *testing.T) {
        artifact := scenario.CreateTestArtifact("vulnerable-app:v1.0.0", map[string]string{
            "dependency": "log4j:2.14.1", // Known vulnerable version
        })
        
        err := scenario.TrackArtifact(artifact)
        assert.NoError(t, err)
    })
    
    // Step 2: Simulate vulnerability disclosure
    t.Run("disclose_vulnerability", func(t *testing.T) {
        vuln := &types.Vulnerability{
            CVE:         "CVE-2021-44228",
            Severity:    "CRITICAL",
            Package:     "log4j",
            VersionSpec: ">=2.0.0,<2.15.0",
        }
        
        err := scenario.DisclosureVulnerability(vuln)
        assert.NoError(t, err)
    })
    
    // Step 3: Verify blast radius calculation
    t.Run("verify_blast_radius", func(t *testing.T) {
        client := scenario.APIClient()
        blastRadius, err := client.GetBlastRadius(context.Background(), "CVE-2021-44228")
        
        assert.NoError(t, err)
        assert.Contains(t, blastRadius.AffectedArtifacts, "vulnerable-app:v1.0.0")
        assert.Equal(t, "CRITICAL", blastRadius.MaxSeverity)
    })
    
    // Step 4: Generate incident response report
    t.Run("generate_incident_report", func(t *testing.T) {
        report, err := scenario.GenerateIncidentReport("CVE-2021-44228")
        assert.NoError(t, err)
        assert.NotEmpty(t, report.AffectedServices)
        assert.NotEmpty(t, report.RecommendedActions)
    })
}
```

## Test Data Management

### Fixtures and Test Data

```go
type TestDataManager struct {
    fixturesDir string
    tempDir     string
}

func (tdm *TestDataManager) LoadFixture(name string) ([]byte, error) {
    path := filepath.Join(tdm.fixturesDir, name)
    return os.ReadFile(path)
}

func (tdm *TestDataManager) CreateTempFile(name, content string) (string, error) {
    path := filepath.Join(tdm.tempDir, name)
    err := os.WriteFile(path, []byte(content), 0644)
    return path, err
}

func (tdm *TestDataManager) Cleanup() error {
    return os.RemoveAll(tdm.tempDir)
}
```

### Sample Test Repository

The `fixtures/sample_repo/` directory contains a complete sample repository:

```
fixtures/sample_repo/
├── .git/                    # Git repository
├── src/                     # Source code
├── Dockerfile               # Container build file
├── go.mod                   # Go module file
├── .provenance.yaml         # Provenance configuration
└── README.md               # Project documentation
```

## Performance and Load Testing

### Load Test Example

```go
func TestProvenanceAPI_LoadTest(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    const (
        concurrency = 10
        requests    = 100
        timeout     = 60 * time.Second
    )
    
    client := testEnv.APIClient()
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    
    var wg sync.WaitGroup
    errors := make(chan error, concurrency)
    
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            
            for j := 0; j < requests/concurrency; j++ {
                buildEvent := generateTestBuildEvent(workerID, j)
                if err := client.TrackBuild(ctx, buildEvent); err != nil {
                    errors <- err
                    return
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for errors
    var errorCount int
    for err := range errors {
        t.Logf("Request error: %v", err)
        errorCount++
    }
    
    assert.Equal(t, 0, errorCount, "Expected no errors during load test")
}
```

## Continuous Integration

### GitHub Actions Configuration

```yaml
name: E2E Tests

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Nightly runs

jobs:
  e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    
    services:
      neo4j:
        image: neo4j:latest
        env:
          NEO4J_AUTH: neo4j/password
        ports:
          - 7687:7687
      
      redis:
        image: redis:latest
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Setup test environment
        run: make e2e-setup
      
      - name: Run E2E tests
        run: make test-e2e
        env:
          E2E_TIMEOUT: 20m
          HEADLESS: true
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: e2e-test-results
          path: |
            test-results/
            screenshots/
            logs/
```

## Debugging and Troubleshooting

### Debug Mode

```bash
# Run with debug logging
DEBUG=true make test-e2e

# Run with browser visible (web tests)
HEADLESS=false make test-e2e

# Preserve test environment after failure
CLEANUP_ON_FAILURE=false make test-e2e
```

### Test Artifacts

Failed tests generate artifacts for debugging:

```
test-artifacts/
├── screenshots/           # Browser screenshots
├── logs/                 # Application logs
├── network-traces/       # Network request traces
└── database-dumps/       # Database state dumps
```

## Best Practices

1. **Test Independence**: Each test should be completely independent
2. **Realistic Data**: Use realistic test data and scenarios
3. **Error Handling**: Test error conditions and edge cases
4. **Performance**: Monitor test execution time and system resources
5. **Cleanup**: Always clean up test data and resources
6. **Documentation**: Document test scenarios and expected outcomes
7. **Maintenance**: Regularly update tests as the system evolves

## Resources

- [E2E Testing Best Practices](https://playwright.dev/docs/best-practices)
- [Go E2E Testing Patterns](https://go.dev/doc/tutorial/add-a-test)
- [ChromeDP Documentation](https://pkg.go.dev/github.com/chromedp/chromedp)
- [Testing with Docker Compose](https://docs.docker.com/compose/test/)