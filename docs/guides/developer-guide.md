# Developer Guide

Comprehensive guide for developers working with and contributing to the Provenance Graph SBOM Linker.

## Table of Contents

- [Development Environment](#development-environment)
- [Architecture Overview](#architecture-overview)
- [API Development](#api-development)
- [Database Operations](#database-operations)
- [Testing Strategy](#testing-strategy)
- [Security Implementation](#security-implementation)
- [Performance Optimization](#performance-optimization)
- [Debugging and Troubleshooting](#debugging-and-troubleshooting)

## Development Environment

### Prerequisites

- Go 1.21 or later
- Docker and Docker Compose
- Make
- Git
- Node.js 18+ (for frontend development)
- Neo4j Desktop (optional, for local development)

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/provenance-graph-sbom-linker.git
cd provenance-graph-sbom-linker

# Start development services
make dev

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
make test
```

### Development Services

```bash
# Start all services
docker-compose up -d

# Services available:
# - Neo4j: http://localhost:7474 (browser), bolt://localhost:7687 (driver)
# - Redis: localhost:6379
# - MinIO: http://localhost:9000 (console), localhost:9001 (API)
# - Jaeger: http://localhost:16686
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000
```

### IDE Configuration

#### VS Code

```json
// .vscode/settings.json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "go.testFlags": ["-v"],
  "go.coverOnSave": true,
  "go.coverageDecorator": {
    "type": "gutter",
    "coveredHighlightColor": "rgba(64,128,128,0.5)",
    "uncoveredHighlightColor": "rgba(128,64,64,0.25)"
  }
}
```

#### GoLand
- Enable Go modules support
- Configure golangci-lint as external tool
- Set up run configurations for services

## Architecture Overview

### Project Structure

```
provenace-graph-sbom-linker/
├── cmd/                    # Main applications
│   ├── server/            # API server
│   ├── worker/            # Background worker
│   └── cli/               # CLI tool
├── pkg/                   # Public library code
│   ├── client/            # Client libraries
│   ├── types/             # Type definitions
│   ├── utils/             # Utility functions
│   └── api/               # API definitions
├── internal/              # Private application code
│   ├── auth/              # Authentication/authorization
│   ├── database/          # Database layer
│   ├── handlers/          # HTTP handlers
│   ├── middleware/        # HTTP middleware
│   ├── services/          # Business logic
│   └── workers/           # Background job processing
├── test/                  # Test files
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   ├── e2e/               # End-to-end tests
│   └── fixtures/          # Test data
├── web/                   # Frontend code
│   ├── src/               # React source
│   ├── public/            # Static assets
│   └── dist/              # Built assets
├── docs/                  # Documentation
├── deploy/                # Deployment configurations
└── scripts/               # Build and utility scripts
```

### Core Components

#### Services Layer

```go
// internal/services/provenance.go
type ProvenanceService struct {
    db     database.DB
    logger logger.Logger
    cache  cache.Cache
}

func (s *ProvenanceService) TrackBuild(ctx context.Context, event *types.BuildEvent) error {
    // Validate input
    if err := s.validateBuildEvent(event); err != nil {
        return fmt.Errorf("invalid build event: %w", err)
    }
    
    // Create graph nodes and relationships
    tx, err := s.db.BeginTx(ctx)
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    defer tx.Rollback()
    
    // Implementation...
    
    return tx.Commit()
}
```

#### Database Layer

```go
// internal/database/neo4j.go
type Neo4jDB struct {
    driver neo4j.Driver
    logger logger.Logger
}

func (db *Neo4jDB) CreateArtifact(ctx context.Context, artifact *types.Artifact) error {
    session := db.driver.NewSession(neo4j.SessionConfig{
        AccessMode: neo4j.AccessModeWrite,
    })
    defer session.Close()
    
    query := `
        CREATE (a:Artifact {
            name: $name,
            version: $version,
            type: $type,
            hash: $hash,
            created_at: datetime()
        })
        RETURN a
    `
    
    _, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
        return tx.Run(query, map[string]interface{}{
            "name":    artifact.Name,
            "version": artifact.Version,
            "type":    artifact.Type,
            "hash":    artifact.Hash,
        })
    })
    
    return err
}
```

## API Development

### REST API Design

#### Handler Pattern

```go
// internal/handlers/provenance.go
type ProvenanceHandler struct {
    service services.ProvenanceService
    logger  logger.Logger
}

func (h *ProvenanceHandler) TrackBuild(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    var event types.BuildEvent
    if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
        h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
        return
    }
    
    if err := h.service.TrackBuild(ctx, &event); err != nil {
        h.logger.Error("Failed to track build", "error", err)
        h.writeError(w, http.StatusInternalServerError, "Failed to track build", err)
        return
    }
    
    h.writeJSON(w, http.StatusCreated, map[string]string{
        "status": "success",
        "id":     event.ID,
    })
}
```

#### Middleware

```go
// internal/middleware/auth.go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        // Validate token
        claims, err := validateJWT(token)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Add claims to context
        ctx := context.WithValue(r.Context(), "user", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### OpenAPI Specification

```yaml
# api/openapi.yaml
openapi: 3.0.3
info:
  title: Provenance Graph SBOM Linker API
  version: 1.0.0
  description: API for tracking software supply chain provenance

paths:
  /api/v1/artifacts:
    post:
      summary: Track a new artifact
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BuildEvent'
      responses:
        '201':
          description: Artifact tracked successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TrackingResponse'
        '400':
          description: Invalid request
        '401':
          description: Unauthorized

components:
  schemas:
    BuildEvent:
      type: object
      required:
        - source_ref
        - commit_hash
        - artifacts
      properties:
        source_ref:
          type: string
          example: "git@github.com:org/repo.git@main"
        commit_hash:
          type: string
          example: "abc123def456"
        artifacts:
          type: array
          items:
            $ref: '#/components/schemas/Artifact'
```

## Database Operations

### Neo4j Patterns

#### Graph Traversal

```cypher
// Find all artifacts derived from a commit
MATCH (c:Commit {hash: $commit_hash})-[:BUILT_INTO*]->(a:Artifact)
RETURN a.name, a.version, a.type, a.hash
ORDER BY a.created_at DESC
```

#### Complex Relationships

```cypher
// Track vulnerability propagation
MATCH (v:Vulnerability {cve: $cve})-[:AFFECTS]->(d:Dependency)
MATCH (a:Artifact)-[:DEPENDS_ON*]->(d)
MATCH (dep:Deployment)-[:RUNS]->(a)
RETURN DISTINCT dep.environment, dep.platform, 
       collect(a.name + ':' + a.version) as affected_artifacts
```

#### Performance Optimization

```cypher
// Use indexes for frequent queries
CREATE INDEX artifact_name_version IF NOT EXISTS
FOR (a:Artifact) ON (a.name, a.version)

CREATE INDEX commit_hash IF NOT EXISTS
FOR (c:Commit) ON (c.hash)

CREATE INDEX vulnerability_cve IF NOT EXISTS
FOR (v:Vulnerability) ON (v.cve)
```

### Transaction Management

```go
// Database transaction pattern
func (s *Service) ComplexOperation(ctx context.Context, data *ComplexData) error {
    return s.db.WithTransaction(ctx, func(tx database.Tx) error {
        // Step 1: Create nodes
        if err := tx.CreateNodes(data.Nodes); err != nil {
            return fmt.Errorf("failed to create nodes: %w", err)
        }
        
        // Step 2: Create relationships
        if err := tx.CreateRelationships(data.Relationships); err != nil {
            return fmt.Errorf("failed to create relationships: %w", err)
        }
        
        // Step 3: Update indexes
        if err := tx.UpdateIndexes(data.IndexUpdates); err != nil {
            return fmt.Errorf("failed to update indexes: %w", err)
        }
        
        return nil
    })
}
```

## Testing Strategy

### Unit Testing

```go
// internal/services/provenance_test.go
func TestProvenanceService_TrackBuild(t *testing.T) {
    tests := []struct {
        name    string
        event   *types.BuildEvent
        setup   func(*mock.DB)
        wantErr bool
    }
    {
        {
            name: "successful build tracking",
            event: &types.BuildEvent{
                SourceRef:  "git@github.com:org/repo.git@main",
                CommitHash: "abc123",
                Artifacts: []types.Artifact{
                    {
                        Name:    "my-app",
                        Version: "v1.0.0",
                        Type:    "container",
                        Hash:    "sha256:def456",
                    },
                },
            },
            setup: func(db *mock.DB) {
                db.EXPECT().BeginTx(gomock.Any()).Return(&mock.Tx{}, nil)
                // Additional expectations...
            },
            wantErr: false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockDB := mock.NewMockDB(ctrl)
            tt.setup(mockDB)
            
            service := services.NewProvenanceService(mockDB, logger.NewNoop(), cache.NewNoop())
            
            err := service.TrackBuild(context.Background(), tt.event)
            if (err != nil) != tt.wantErr {
                t.Errorf("TrackBuild() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Integration Testing

```go
// test/integration/provenance_test.go
func TestProvenanceIntegration(t *testing.T) {
    // Setup test environment
    testDB := setupTestDatabase(t)
    defer cleanupTestDatabase(t, testDB)
    
    server := setupTestServer(t, testDB)
    defer server.Close()
    
    client := api.NewClient(server.URL)
    
    // Test complete workflow
    t.Run("complete provenance workflow", func(t *testing.T) {
        // 1. Track build
        buildEvent := &types.BuildEvent{
            SourceRef:  "git@github.com:test/repo.git@main",
            CommitHash: "abc123def456",
            Artifacts: []types.Artifact{
                {
                    Name:    "test-app",
                    Version: "v1.0.0",
                    Type:    "container",
                    Hash:    "sha256:abcdef123456",
                },
            },
        }
        
        err := client.TrackBuild(context.Background(), buildEvent)
        require.NoError(t, err)
        
        // 2. Query provenance
        provenance, err := client.GetProvenance(context.Background(), "test-app:v1.0.0")
        require.NoError(t, err)
        require.NotNil(t, provenance)
        
        // 3. Verify relationships
        assert.Equal(t, "abc123def456", provenance.SourceCommit)
        assert.Len(t, provenance.Artifacts, 1)
    })
}
```

### End-to-End Testing

```go
// test/e2e/supply_chain_test.go
func TestSupplyChainE2E(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping E2E test in short mode")
    }
    
    // Setup complete environment
    env := setupE2EEnvironment(t)
    defer env.Cleanup()
    
    // Test complete supply chain tracking
    t.Run("full supply chain tracking", func(t *testing.T) {
        // 1. Simulate git commit
        commit := env.CreateTestCommit("Initial commit")
        
        // 2. Simulate CI build
        build := env.TriggerBuild(commit.Hash)
        
        // 3. Generate SBOM
        sbom := env.GenerateSBOM(build.Artifacts[0])
        
        // 4. Sign artifact
        signature := env.SignArtifact(build.Artifacts[0])
        
        // 5. Deploy to staging
        deployment := env.Deploy(build.Artifacts[0], "staging")
        
        // 6. Verify complete provenance chain
        chain, err := env.Client.GetSupplyChain(context.Background(), deployment.ID)
        require.NoError(t, err)
        
        // Assertions
        assert.Equal(t, commit.Hash, chain.Source.Commit)
        assert.NotEmpty(t, chain.SBOM)
        assert.NotEmpty(t, chain.Signature)
        assert.Equal(t, "staging", chain.Deployment.Environment)
    })
}
```

## Security Implementation

### Authentication and Authorization

```go
// internal/auth/jwt.go
type JWTManager struct {
    secret     []byte
    expiration time.Duration
}

func (j *JWTManager) GenerateToken(userID string, roles []string) (string, error) {
    claims := jwt.MapClaims{
        "user_id": userID,
        "roles":   roles,
        "exp":     time.Now().Add(j.expiration).Unix(),
        "iat":     time.Now().Unix(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(j.secret)
}

func (j *JWTManager) ValidateToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return j.secret, nil
    })
}
```

### Input Validation

```go
// internal/validation/validator.go
type Validator struct {
    validate *validator.Validate
}

func NewValidator() *Validator {
    v := validator.New()
    
    // Custom validators
    v.RegisterValidation("git_ref", validateGitRef)
    v.RegisterValidation("sha256", validateSHA256)
    v.RegisterValidation("semver", validateSemVer)
    
    return &Validator{validate: v}
}

func (v *Validator) ValidateBuildEvent(event *types.BuildEvent) error {
    if err := v.validate.Struct(event); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    // Additional business logic validation
    if len(event.Artifacts) == 0 {
        return errors.New("at least one artifact is required")
    }
    
    return nil
}

func validateGitRef(fl validator.FieldLevel) bool {
    ref := fl.Field().String()
    // Git reference validation logic
    return regexp.MustCompile(`^git@.*\.git@.*$`).MatchString(ref)
}
```

### Cryptographic Operations

```go
// internal/crypto/signing.go
type SignatureManager struct {
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
}

func (s *SignatureManager) SignArtifact(artifact *types.Artifact) (*types.Signature, error) {
    // Create canonical representation
    canonical, err := s.canonicalize(artifact)
    if err != nil {
        return nil, fmt.Errorf("failed to canonicalize artifact: %w", err)
    }
    
    // Create hash
    hash := sha256.Sum256(canonical)
    
    // Sign hash
    signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
    if err != nil {
        return nil, fmt.Errorf("failed to sign artifact: %w", err)
    }
    
    return &types.Signature{
        Algorithm: "RSA-SHA256",
        Value:     base64.StdEncoding.EncodeToString(signature),
        PublicKey: s.publicKeyPEM(),
        Timestamp: time.Now(),
    }, nil
}
```

## Performance Optimization

### Caching Strategy

```go
// internal/cache/redis.go
type RedisCache struct {
    client redis.Client
    ttl    time.Duration
}

func (c *RedisCache) GetProvenance(ctx context.Context, artifactID string) (*types.Provenance, error) {
    key := fmt.Sprintf("provenance:%s", artifactID)
    
    // Try cache first
    cached, err := c.client.Get(ctx, key).Result()
    if err == nil {
        var provenance types.Provenance
        if err := json.Unmarshal([]byte(cached), &provenance); err == nil {
            return &provenance, nil
        }
    }
    
    // Cache miss - would fetch from database
    return nil, cache.ErrMiss
}

func (c *RedisCache) SetProvenance(ctx context.Context, artifactID string, provenance *types.Provenance) error {
    key := fmt.Sprintf("provenance:%s", artifactID)
    
    data, err := json.Marshal(provenance)
    if err != nil {
        return fmt.Errorf("failed to marshal provenance: %w", err)
    }
    
    return c.client.Set(ctx, key, data, c.ttl).Err()
}
```

### Database Query Optimization

```go
// Batch operations for better performance
func (db *Neo4jDB) BatchCreateArtifacts(ctx context.Context, artifacts []*types.Artifact) error {
    session := db.driver.NewSession(neo4j.SessionConfig{
        AccessMode: neo4j.AccessModeWrite,
    })
    defer session.Close()
    
    query := `
        UNWIND $artifacts AS artifact
        CREATE (a:Artifact {
            name: artifact.name,
            version: artifact.version,
            type: artifact.type,
            hash: artifact.hash,
            created_at: datetime()
        })
    `
    
    params := map[string]interface{}{
        "artifacts": artifactsToParams(artifacts),
    }
    
    _, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
        return tx.Run(query, params)
    })
    
    return err
}
```

## Debugging and Troubleshooting

### Logging

```go
// internal/logger/structured.go
type StructuredLogger struct {
    logger *slog.Logger
}

func (l *StructuredLogger) TrackBuild(ctx context.Context, event *types.BuildEvent) {
    l.logger.InfoContext(ctx, "Tracking build event",
        "source_ref", event.SourceRef,
        "commit_hash", event.CommitHash,
        "artifact_count", len(event.Artifacts),
        "trace_id", getTraceID(ctx),
    )
}

func (l *StructuredLogger) Error(ctx context.Context, msg string, err error, fields ...interface{}) {
    args := []interface{}{"error", err, "trace_id", getTraceID(ctx)}
    args = append(args, fields...)
    l.logger.ErrorContext(ctx, msg, args...)
}
```

### Metrics and Observability

```go
// internal/metrics/prometheus.go
type PrometheusMetrics struct {
    buildsTracked    prometheus.Counter
    queryDuration    prometheus.Histogram
    activeConnections prometheus.Gauge
}

func NewPrometheusMetrics() *PrometheusMetrics {
    m := &PrometheusMetrics{
        buildsTracked: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "provenance_builds_tracked_total",
            Help: "Total number of build events tracked",
        }),
        queryDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name:    "provenance_query_duration_seconds",
            Help:    "Duration of provenance queries",
            Buckets: prometheus.DefBuckets,
        }),
        activeConnections: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "provenance_db_connections_active",
            Help: "Number of active database connections",
        }),
    }
    
    prometheus.MustRegister(m.buildsTracked, m.queryDuration, m.activeConnections)
    return m
}
```

### Debugging Tools

```bash
# Enable debug logging
export LOG_LEVEL=debug

# Enable database query logging
export NEO4J_LOG_QUERIES=true

# Enable profiling
export ENABLE_PPROF=true

# Run with profiling
go run -race ./cmd/server --profile

# Analyze heap dump
go tool pprof http://localhost:6060/debug/pprof/heap

# Analyze CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

## Best Practices

### Code Organization

1. **Domain-Driven Design**: Organize code around business domains
2. **Dependency Injection**: Use interfaces for testability
3. **Error Handling**: Wrap errors with context
4. **Configuration**: Use environment variables with defaults
5. **Documentation**: Document all public APIs with examples

### Performance

1. **Caching**: Cache frequently accessed data
2. **Batching**: Batch database operations when possible
3. **Indexing**: Create appropriate database indexes
4. **Connection Pooling**: Reuse database connections
5. **Async Processing**: Use background workers for heavy operations

### Security

1. **Input Validation**: Validate and sanitize all inputs
2. **Authentication**: Implement proper authentication mechanisms
3. **Authorization**: Use RBAC for access control
4. **Secrets Management**: Never hardcode secrets
5. **Audit Logging**: Log all security-relevant events

### Testing

1. **Test Pyramid**: Unit > Integration > E2E tests
2. **Coverage**: Aim for >80% test coverage
3. **Mocking**: Mock external dependencies
4. **Test Data**: Use factories for test data generation
5. **CI/CD**: Run tests on every commit

## Resources

- [Go Best Practices](https://golang.org/doc/effective_go.html)
- [Neo4j Developer Guide](https://neo4j.com/developer/)
- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [Prometheus Metrics](https://prometheus.io/docs/practices/naming/)
- [OWASP Secure Coding](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

For more specific guidance, see:
- [API Reference](../api/README.md)
- [Database Schema](../database/schema.md)
- [Deployment Guide](../deployment/README.md)
- [Contributing Guidelines](../../CONTRIBUTING.md)