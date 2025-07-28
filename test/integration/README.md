# Integration Tests

This directory contains integration tests for the Provenance Graph SBOM Linker.

## Overview

Integration tests verify that different components work correctly together. They test interactions between services, databases, external APIs, and other system components.

## Structure

```
integration/
├── README.md                 # This file
├── api/                     # API integration tests
│   ├── provenance_test.go   # Provenance API tests
│   ├── sbom_test.go         # SBOM API tests
│   └── auth_test.go         # Authentication tests
├── database/                # Database integration tests
│   ├── neo4j_test.go        # Neo4j integration tests
│   └── redis_test.go        # Redis integration tests
├── external/                # External service tests
│   ├── github_test.go       # GitHub API integration
│   ├── registry_test.go     # Container registry tests
│   └── sigstore_test.go     # Sigstore integration
└── scenarios/               # End-to-end scenario tests
    ├── build_flow_test.go   # Complete build flow
    └── compliance_test.go   # Compliance workflow
```

## Test Environment

Integration tests require running services:

### Prerequisites
```bash
# Start test environment
make dev

# Or manually start services
docker-compose -f docker-compose.test.yml up -d
```

### Required Services
- Neo4j (localhost:7687)
- Redis (localhost:6379)
- MinIO (localhost:9000)
- Test API server

## Test Configuration

Tests use build tags to separate from unit tests:

```go
//go:build integration
// +build integration

package integration

import (
    "testing"
    "github.com/stretchr/testify/assert"
)
```

## Running Integration Tests

```bash
# All integration tests
make test-integration

# Specific test file
go test -tags=integration ./test/integration/api/

# With verbose output
go test -tags=integration -v ./test/integration/...

# With race detection
go test -tags=integration -race ./test/integration/...
```

## Test Structure

### Setup and Teardown

```go
func TestMain(m *testing.M) {
    // Setup test environment
    setupFunc := func() {
        // Initialize test database
        testDB = setupTestDatabase()
        
        // Start test server
        testServer = startTestServer()
    }
    
    // Cleanup
    teardownFunc := func() {
        testServer.Close()
        testDB.Close()
    }
    
    code := testutil.RunWithSetup(m, setupFunc, teardownFunc)
    os.Exit(code)
}
```

### Test Example

```go
func TestProvenanceAPI_TrackBuild_Integration(t *testing.T) {
    // Arrange
    client := api.NewClient(testServer.URL)
    buildEvent := &types.BuildEvent{
        SourceRef:  "git@github.com:test/repo.git@main",
        CommitHash: "abc123",
        Artifacts: []types.Artifact{
            {
                Name:    "test-app",
                Version: "v1.0.0",
                Type:    "container",
                Hash:    "sha256:def456",
            },
        },
    }
    
    // Act
    err := client.TrackBuild(context.Background(), buildEvent)
    
    // Assert
    assert.NoError(t, err)
    
    // Verify data was stored
    provenance, err := client.GetProvenance(context.Background(), "test-app:v1.0.0")
    assert.NoError(t, err)
    assert.Equal(t, "abc123", provenance.SourceCommit)
}
```

## Database Tests

### Neo4j Integration

```go
func TestNeo4j_CreateArtifact(t *testing.T) {
    db := testutil.NewTestNeo4j(t)
    defer db.Close()
    
    artifact := &types.Artifact{
        Name:    "test-artifact",
        Version: "1.0.0",
        Type:    "binary",
        Hash:    "sha256:abc123",
    }
    
    err := db.CreateArtifact(context.Background(), artifact)
    assert.NoError(t, err)
    
    // Verify artifact exists
    exists, err := db.ArtifactExists(context.Background(), artifact.Name, artifact.Version)
    assert.NoError(t, err)
    assert.True(t, exists)
}
```

### Redis Integration

```go
func TestRedis_CacheOperations(t *testing.T) {
    cache := testutil.NewTestRedis(t)
    defer cache.Close()
    
    key := "test-key"
    value := "test-value"
    
    // Set value
    err := cache.Set(context.Background(), key, value, time.Minute)
    assert.NoError(t, err)
    
    // Get value
    retrieved, err := cache.Get(context.Background(), key)
    assert.NoError(t, err)
    assert.Equal(t, value, retrieved)
}
```

## External Service Tests

### GitHub API Integration

```go
func TestGitHub_WebhookHandling(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping GitHub integration test in short mode")
    }
    
    // This test requires GITHUB_TOKEN environment variable
    token := os.Getenv("GITHUB_TOKEN")
    if token == "" {
        t.Skip("GITHUB_TOKEN not set")
    }
    
    client := github.NewClient(token)
    
    // Test webhook processing
    webhook := &github.PushEvent{
        Repository: &github.Repository{
            FullName: github.String("test/repo"),
        },
        HeadCommit: &github.Commit{
            ID: github.String("abc123"),
        },
    }
    
    err := processGitHubWebhook(client, webhook)
    assert.NoError(t, err)
}
```

### Container Registry Tests

```go
func TestRegistry_PullImage(t *testing.T) {
    registry := testutil.NewTestRegistry(t)
    defer registry.Close()
    
    // Push test image
    testImage := "test-app:latest"
    err := registry.Push(testImage, testImageData)
    assert.NoError(t, err)
    
    // Pull and verify
    manifest, err := registry.GetManifest(testImage)
    assert.NoError(t, err)
    assert.NotNil(t, manifest)
}
```

## Scenario Tests

### Complete Build Flow

```go
func TestBuildFlow_EndToEnd(t *testing.T) {
    // This test simulates a complete build flow
    
    // 1. Receive webhook from GitHub
    webhook := createTestWebhook()
    err := handleGitHubWebhook(webhook)
    assert.NoError(t, err)
    
    // 2. Process build event
    buildEvent := createBuildEvent(webhook)
    err = trackBuild(buildEvent)
    assert.NoError(t, err)
    
    // 3. Generate SBOM
    sbom, err := generateSBOM(buildEvent.Artifacts[0])
    assert.NoError(t, err)
    assert.NotNil(t, sbom)
    
    // 4. Sign artifact
    signature, err := signArtifact(buildEvent.Artifacts[0])
    assert.NoError(t, err)
    assert.NotEmpty(t, signature)
    
    // 5. Verify complete provenance chain
    provenance, err := getCompleteProvenance(buildEvent.Artifacts[0].Name)
    assert.NoError(t, err)
    assert.Equal(t, webhook.HeadCommit.ID, provenance.SourceCommit)
    assert.NotNil(t, provenance.SBOM)
    assert.NotNil(t, provenance.Signature)
}
```

## Test Data Management

### Fixtures
```go
func loadTestFixture(t *testing.T, filename string) []byte {
    data, err := os.ReadFile(filepath.Join("../fixtures", filename))
    require.NoError(t, err)
    return data
}
```

### Cleanup
```go
func TestWithCleanup(t *testing.T) {
    // Create test data
    artifact := createTestArtifact()
    
    // Ensure cleanup
    t.Cleanup(func() {
        deleteTestArtifact(artifact.ID)
    })
    
    // Test implementation
}
```

## Performance Considerations

### Timeouts
```go
func TestWithTimeout(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Test with context timeout
    err := longRunningOperation(ctx)
    assert.NoError(t, err)
}
```

### Parallel Execution
```go
func TestParallel(t *testing.T) {
    tests := []struct{
        name string
        // test cases
    }{
        // test data
    }
    
    for _, tt := range tests {
        tt := tt // capture loop variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            // test implementation
        })
    }
}
```

## Configuration

### Environment Variables
```bash
# Test environment configuration
export TEST_NEO4J_URI=bolt://localhost:7687
export TEST_REDIS_URL=redis://localhost:6379
export TEST_MINIO_ENDPOINT=localhost:9000
export TEST_DATABASE_CLEANUP=true
```

### Test Configuration File
```yaml
# test-config.yaml
database:
  neo4j:
    uri: bolt://localhost:7687
    username: neo4j
    password: test
  redis:
    url: redis://localhost:6379/1

storage:
  endpoint: localhost:9000
  bucket: test-artifacts

timeouts:
  default: 30s
  database: 10s
  external: 60s
```

## CI/CD Integration

Integration tests run in the CI pipeline after unit tests:

```yaml
# .github/workflows/test.yml
- name: Run Integration Tests
  run: |
    make dev
    make test-integration
  env:
    TEST_TIMEOUT: 300s
```

## Troubleshooting

### Common Issues

1. **Service not available**: Ensure test services are running
2. **Port conflicts**: Check if ports are already in use
3. **Permission issues**: Verify database permissions
4. **Network timeouts**: Increase timeout values for slow tests

### Debug Mode
```bash
# Run with debug logging
DEBUG=true make test-integration

# Run specific test with verbose output
go test -tags=integration -v -run TestSpecificTest ./test/integration/
```

## Best Practices

1. **Test Isolation**: Use separate databases/namespaces per test
2. **Cleanup**: Always clean up test data
3. **Retry Logic**: Implement retries for flaky external services
4. **Timeouts**: Set appropriate timeouts for all operations
5. **Mocking**: Mock external services when possible
6. **Documentation**: Document test setup requirements

## Resources

- [Go Integration Testing](https://golang.org/doc/tutorial/add-a-test)
- [Testcontainers](https://golang.testcontainers.org/) for service dependencies
- [Testing with Docker Compose](https://docs.docker.com/compose/test/)
- [Database Testing Patterns](https://go.dev/doc/database/testing)