package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// TestSuite provides comprehensive testing utilities
type TestSuite struct {
	DB       *database.Neo4jDB
	Server   *httptest.Server
	Router   *gin.Engine
	Config   *config.Config
	TestData *TestData
}

// TestData contains common test fixtures
type TestData struct {
	Artifacts []types.Artifact
	Sources   []types.Source
	SBOMs     []types.SBOM
	Users     []TestUser
}

type TestUser struct {
	ID       string
	Username string
	Email    string
	Roles    []string
}

// MockDatabase provides a mock implementation for testing
type MockDatabase struct {
	artifacts   map[string]*types.Artifact
	sources     map[string]*types.Source
	buildEvents map[string]*types.BuildEvent
	failQueries map[string]error
}

func NewMockDatabase() *MockDatabase {
	return &MockDatabase{
		artifacts:   make(map[string]*types.Artifact),
		sources:     make(map[string]*types.Source),
		buildEvents: make(map[string]*types.BuildEvent),
		failQueries: make(map[string]error),
	}
}

func (m *MockDatabase) CreateArtifact(ctx context.Context, artifact *types.Artifact) error {
	if err := m.failQueries["CreateArtifact"]; err != nil {
		return err
	}
	m.artifacts[artifact.ID.String()] = artifact
	return nil
}

func (m *MockDatabase) GetArtifact(ctx context.Context, id string) (*types.Artifact, error) {
	if err := m.failQueries["GetArtifact"]; err != nil {
		return nil, err
	}
	artifact, exists := m.artifacts[id]
	if !exists {
		return nil, fmt.Errorf("artifact not found")
	}
	return artifact, nil
}

func (m *MockDatabase) CreateSource(ctx context.Context, source *types.Source) error {
	if err := m.failQueries["CreateSource"]; err != nil {
		return err
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *MockDatabase) CreateBuildEvent(ctx context.Context, buildEvent *types.BuildEvent) error {
	if err := m.failQueries["CreateBuildEvent"]; err != nil {
		return err
	}
	m.buildEvents[buildEvent.ID.String()] = buildEvent
	return nil
}

func (m *MockDatabase) CreateProvenanceLink(ctx context.Context, fromID, toID, linkType string) error {
	if err := m.failQueries["CreateProvenanceLink"]; err != nil {
		return err
	}
	// Mock implementation - just store the relationship
	return nil
}

func (m *MockDatabase) GetProvenanceGraph(ctx context.Context, artifactID string, depth int) (*types.ProvenanceGraph, error) {
	if err := m.failQueries["GetProvenanceGraph"]; err != nil {
		return nil, err
	}
	
	// Return a mock provenance graph
	return &types.ProvenanceGraph{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Nodes:     []types.Node{},
		Edges:     []types.Edge{},
		Metadata:  make(map[string]string),
	}, nil
}

func (m *MockDatabase) Close() error {
	return nil
}

// SetQueryFailure makes a specific query method return an error
func (m *MockDatabase) SetQueryFailure(method string, err error) {
	m.failQueries[method] = err
}

// ClearQueryFailures removes all query failures
func (m *MockDatabase) ClearQueryFailures() {
	m.failQueries = make(map[string]error)
}

// Test data generators
func GenerateTestArtifact() types.Artifact {
	return types.Artifact{
		ID:        uuid.New(),
		Name:      "test-artifact",
		Version:   "1.0.0",
		Type:      types.ArtifactTypeContainer,
		Hash:      "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
		Size:      1024,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  make(map[string]string),
	}
}

func GenerateTestSource() types.Source {
	return types.Source{
		ID:         uuid.New(),
		Type:       types.SourceTypeGit,
		URL:        "https://github.com/example/repo",
		Branch:     "main",
		CommitHash: "abcd1234567890abcd1234567890abcd1234567890",
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]string),
	}
}

func GenerateTestSBOM() types.SBOM {
	return types.SBOM{
		ID:        uuid.New(),
		Format:    types.SBOMFormatCycloneDX,
		Version:   "1.0",
		CreatedAt: time.Now(),
		CreatedBy: "test-generator",
		Hash:      "sha256:test-sbom-hash",
		Metadata:  make(map[string]string),
		Components: []types.Component{
			{
				ID:          uuid.New(),
				Name:        "test-component",
				Version:     "1.0.0",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"MIT"},
				Description: "Test component for testing",
				Metadata:    make(map[string]string),
			},
		},
	}
}

func GenerateTestBuildEvent() types.BuildEvent {
	return types.BuildEvent{
		ID:          uuid.New(),
		SourceRef:   "git@github.com:example/repo.git",
		CommitHash:  "abcd1234567890abcd1234567890abcd1234567890",
		BuildSystem: "github-actions",
		Timestamp:   time.Now(),
		Metadata:    make(map[string]string),
		Artifacts:   []types.Artifact{GenerateTestArtifact()},
	}
}

// HTTP testing utilities
type APITestCase struct {
	Name           string
	Method         string
	URL            string
	Body           interface{}
	Headers        map[string]string
	ExpectedStatus int
	ExpectedBody   interface{}
	SetupFunc      func(*MockDatabase)
	ValidateFunc   func(*testing.T, *httptest.ResponseRecorder)
}

func (tc *APITestCase) Run(t *testing.T, router *gin.Engine, mockDB *MockDatabase) {
	t.Run(tc.Name, func(t *testing.T) {
		// Setup
		if tc.SetupFunc != nil {
			tc.SetupFunc(mockDB)
		}
		
		// Prepare request body
		var bodyReader *strings.Reader
		if tc.Body != nil {
			bodyJSON, err := json.Marshal(tc.Body)
			require.NoError(t, err)
			bodyReader = strings.NewReader(string(bodyJSON))
		} else {
			bodyReader = strings.NewReader("")
		}
		
		// Create request
		req, err := http.NewRequest(tc.Method, tc.URL, bodyReader)
		require.NoError(t, err)
		
		// Set headers
		if tc.Headers != nil {
			for key, value := range tc.Headers {
				req.Header.Set(key, value)
			}
		}
		if tc.Body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		
		// Execute request
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Validate status code
		assert.Equal(t, tc.ExpectedStatus, w.Code)
		
		// Validate response body if expected
		if tc.ExpectedBody != nil {
			var actualBody interface{}
			err := json.Unmarshal(w.Body.Bytes(), &actualBody)
			require.NoError(t, err)
			
			expectedJSON, _ := json.Marshal(tc.ExpectedBody)
			actualJSON, _ := json.Marshal(actualBody)
			assert.JSONEq(t, string(expectedJSON), string(actualJSON))
		}
		
		// Custom validation
		if tc.ValidateFunc != nil {
			tc.ValidateFunc(t, w)
		}
		
		// Cleanup
		mockDB.ClearQueryFailures()
	})
}

// Performance testing utilities
type PerformanceTest struct {
	Name           string
	SetupFunc      func() interface{}
	TestFunc       func(interface{}) error
	Iterations     int
	MaxDuration    time.Duration
	MaxMemoryMB    int
}

func (pt *PerformanceTest) Run(t *testing.T) {
	t.Run(pt.Name, func(t *testing.T) {
		if pt.Iterations == 0 {
			pt.Iterations = 100
		}
		
		// Setup
		var testData interface{}
		if pt.SetupFunc != nil {
			testData = pt.SetupFunc()
		}
		
		// Measure performance
		start := time.Now()
		
		for i := 0; i < pt.Iterations; i++ {
			err := pt.TestFunc(testData)
			require.NoError(t, err)
		}
		
		duration := time.Since(start)
		avgDuration := duration / time.Duration(pt.Iterations)
		
		// Validate performance constraints
		if pt.MaxDuration > 0 {
			assert.Less(t, avgDuration, pt.MaxDuration, 
				"Average operation duration exceeded maximum: %v > %v", avgDuration, pt.MaxDuration)
		}
		
		t.Logf("Performance test '%s': %d iterations, avg %v per operation", 
			pt.Name, pt.Iterations, avgDuration)
	})
}

// Security testing utilities
type SecurityTest struct {
	Name        string
	Input       string
	ExpectedErr bool
	ThreatType  string
}

func (st *SecurityTest) RunInputValidation(t *testing.T, validator func(string) error) {
	t.Run(fmt.Sprintf("%s_%s", st.Name, st.ThreatType), func(t *testing.T) {
		err := validator(st.Input)
		
		if st.ExpectedErr {
			assert.Error(t, err, "Expected validation error for input: %s", st.Input)
		} else {
			assert.NoError(t, err, "Unexpected validation error for input: %s", st.Input)
		}
	})
}

// Common security test cases
func GetSecurityTestCases() []SecurityTest {
	return []SecurityTest{
		{"SQL_Injection_Union", "' UNION SELECT * FROM users--", true, "sql_injection"},
		{"SQL_Injection_Drop", "'; DROP TABLE users; --", true, "sql_injection"},
		{"XSS_Script_Tag", "<script>alert('xss')</script>", true, "xss"},
		{"XSS_Javascript_URL", "javascript:alert('xss')", true, "xss"},
		{"Path_Traversal", "../../../etc/passwd", true, "path_traversal"},
		{"Command_Injection", "test; rm -rf /", true, "command_injection"},
		{"Valid_Input", "normal-artifact-name", false, "valid"},
		{"Valid_Version", "1.0.0", false, "valid"},
		{"Valid_URL", "https://github.com/example/repo", false, "valid"},
	}
}

// Test assertion helpers
func AssertValidationError(t *testing.T, err error, expectedCode string) {
	assert.Error(t, err)
	// Add custom validation error type checking when implemented
}

func AssertNoValidationError(t *testing.T, err error) {
	assert.NoError(t, err)
}

// Benchmark utilities
func BenchmarkFunction(b *testing.B, fn func()) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn()
	}
}

func BenchmarkWithSetup(b *testing.B, setup func() interface{}, fn func(interface{})) {
	data := setup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(data)
	}
}

// Integration test utilities
func SetupTestEnvironment(t *testing.T) (*TestSuite, func()) {
	// Setup test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:        8080,
			Environment: "test",
		},
		Database: config.DatabaseConfig{
			URI:      "bolt://localhost:7687",
			Username: "neo4j",
			Password: "testpassword",
		},
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "json",
		},
	}
	
	// Setup Gin router in test mode
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	testSuite := &TestSuite{
		// DB:     realDB,  // Use real DB for integration tests
		Router:  router,
		Config:  cfg,
		TestData: generateTestData(),
	}
	
	// Return cleanup function
	cleanup := func() {
		gin.SetMode(gin.ReleaseMode)
		if testSuite.Server != nil {
			testSuite.Server.Close()
		}
		if testSuite.DB != nil {
			testSuite.DB.Close()
		}
	}
	
	return testSuite, cleanup
}

func generateTestData() *TestData {
	return &TestData{
		Artifacts: []types.Artifact{
			GenerateTestArtifact(),
			GenerateTestArtifact(),
		},
		Sources: []types.Source{
			GenerateTestSource(),
		},
		SBOMs: []types.SBOM{
			GenerateTestSBOM(),
		},
		Users: []TestUser{
			{ID: "user1", Username: "testuser", Email: "test@example.com", Roles: []string{"user"}},
			{ID: "admin1", Username: "admin", Email: "admin@example.com", Roles: []string{"admin"}},
		},
	}
}
