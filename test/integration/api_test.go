package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/api"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type APITestSuite struct {
	suite.Suite
	router *gin.Engine
	config *config.Config
}

func (suite *APITestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)
	
	suite.config = &config.Config{
		Server: config.ServerConfig{
			Port:        8080,
			Environment: "test",
		},
		Security: config.SecurityConfig{
			CORSOrigins: []string{"*"},
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	suite.router = api.SetupRoutes(nil, suite.config)
}

func (suite *APITestSuite) TestHealthEndpoint() {
	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(suite.T(), err)

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(suite.T(), err)
	
	assert.Equal(suite.T(), "healthy", response["status"])
	assert.Equal(suite.T(), "provenance-graph-sbom-linker", response["service"])
}

func (suite *APITestSuite) TestVersionEndpoint() {
	req, err := http.NewRequest("GET", "/api/v1/version", nil)
	require.NoError(suite.T(), err)

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), response, "version")
	assert.Contains(suite.T(), response, "commit")
	assert.Contains(suite.T(), response, "date")
}

func (suite *APITestSuite) TestCORSHeaders() {
	req, err := http.NewRequest("OPTIONS", "/api/v1/version", nil)
	require.NoError(suite.T(), err)
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusNoContent, w.Code)
	assert.Equal(suite.T(), "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(suite.T(), w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(suite.T(), w.Header().Get("Access-Control-Allow-Methods"), "POST")
}

func (suite *APITestSuite) TestSecurityHeaders() {
	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(suite.T(), err)

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(suite.T(), "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Contains(suite.T(), w.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	assert.Equal(suite.T(), "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

func (suite *APITestSuite) TestRateLimiting() {
	endpoint := "/health"
	
	for i := 0; i < 100; i++ {
		req, err := http.NewRequest("GET", endpoint, nil)
		require.NoError(suite.T(), err)

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.True(suite.T(), w.Code == http.StatusOK || w.Code == http.StatusTooManyRequests)
	}
}

func (suite *APITestSuite) TestInvalidJSONPayload() {
	invalidJSON := `{"name": "test", "invalid": json}`
	
	req, err := http.NewRequest("POST", "/api/v1/artifacts", bytes.NewBuffer([]byte(invalidJSON)))
	require.NoError(suite.T(), err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

func (suite *APITestSuite) TestLargePayload() {
	largePayload := make(map[string]interface{})
	largePayload["name"] = "test-artifact"
	largePayload["version"] = "1.0.0"
	largePayload["type"] = "container"
	largePayload["data"] = string(make([]byte, 10*1024*1024))

	jsonData, err := json.Marshal(largePayload)
	require.NoError(suite.T(), err)

	req, err := http.NewRequest("POST", "/api/v1/artifacts", bytes.NewBuffer(jsonData))
	require.NoError(suite.T(), err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.True(suite.T(), w.Code == http.StatusBadRequest || w.Code == http.StatusRequestEntityTooLarge)
}

func (suite *APITestSuite) TestConcurrentRequests() {
	const numRequests = 50
	const numWorkers = 10

	jobs := make(chan int, numRequests)
	results := make(chan int, numRequests)

	for i := 0; i < numWorkers; i++ {
		go func() {
			for j := range jobs {
				req, err := http.NewRequest("GET", "/health", nil)
				if err != nil {
					results <- http.StatusInternalServerError
					continue
				}

				w := httptest.NewRecorder()
				suite.router.ServeHTTP(w, req)
				results <- w.Code
			}
		}()
	}

	for i := 0; i < numRequests; i++ {
		jobs <- i
	}
	close(jobs)

	successCount := 0
	for i := 0; i < numRequests; i++ {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}

	assert.True(suite.T(), successCount > numRequests*0.8, "Expected at least 80%% success rate")
}

func (suite *APITestSuite) TestResponseTimeouts() {
	req, err := http.NewRequest("GET", "/api/v1/artifacts?limit=1000", nil)
	require.NoError(suite.T(), err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	assert.True(suite.T(), w.Code != http.StatusRequestTimeout)
}

func (suite *APITestSuite) TestInputSanitization() {
	maliciousPayloads := []map[string]interface{}{
		{
			"name":    "<script>alert('xss')</script>",
			"version": "1.0.0",
			"type":    "container",
		},
		{
			"name":    "test'; DROP TABLE artifacts; --",
			"version": "1.0.0",
			"type":    "container",
		},
		{
			"name":    string(make([]byte, 10000)),
			"version": "1.0.0",
			"type":    "container",
		},
	}

	for _, payload := range maliciousPayloads {
		jsonData, err := json.Marshal(payload)
		require.NoError(suite.T(), err)

		req, err := http.NewRequest("POST", "/api/v1/artifacts", bytes.NewBuffer(jsonData))
		require.NoError(suite.T(), err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.True(suite.T(), w.Code == http.StatusBadRequest || w.Code == http.StatusUnprocessableEntity,
			"Malicious payload should be rejected: %v", payload["name"])
	}
}

func (suite *APITestSuite) TestErrorHandling() {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "Not found",
			method:         "GET",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Method not allowed",
			method:         "DELETE",
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		suite.T().Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			require.NoError(t, err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func (suite *APITestSuite) TestProvenanceWorkflow() {
	artifactID := uuid.New().String()

	steps := []struct {
		name           string
		method         string
		path           string
		payload        interface{}
		expectedStatus int
	}{
		{
			name:   "Create artifact",
			method: "POST",
			path:   "/api/v1/artifacts",
			payload: map[string]interface{}{
				"name":     fmt.Sprintf("workflow-artifact-%s", artifactID),
				"version":  "1.0.0",
				"type":     "container",
				"hash":     "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				"size":     1024,
				"metadata": map[string]string{"workflow": "test"},
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Get artifact",
			method:         "GET",
			path:           fmt.Sprintf("/api/v1/artifacts/%s", artifactID),
			payload:        nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "List artifacts",
			method:         "GET",
			path:           "/api/v1/artifacts",
			payload:        nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Generate SBOM",
			method: "POST",
			path:   "/api/v1/sbom/generate",
			payload: map[string]interface{}{
				"artifact_id": artifactID,
				"format":      "cyclonedx",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Get provenance",
			method: "GET",
			path:   fmt.Sprintf("/api/v1/provenance/%s", artifactID),
			payload: nil,
			expectedStatus: http.StatusOK,
		},
	}

	for _, step := range steps {
		suite.T().Run(step.name, func(t *testing.T) {
			var req *http.Request
			var err error

			if step.payload != nil {
				jsonData, marshalErr := json.Marshal(step.payload)
				require.NoError(t, marshalErr)
				req, err = http.NewRequest(step.method, step.path, bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(step.method, step.path, nil)
			}
			require.NoError(t, err)

			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, step.expectedStatus, w.Code, "Step: %s, Response: %s", step.name, w.Body.String())

			if w.Code >= 200 && w.Code < 300 && w.Body.Len() > 0 {
				var response interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err, "Response should be valid JSON")
			}
		})
	}
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

func BenchmarkAPIEndpoints(b *testing.B) {
	gin.SetMode(gin.TestMode)
	
	config := &config.Config{
		Server: config.ServerConfig{
			Environment: "test",
		},
		Security: config.SecurityConfig{
			CORSOrigins: []string{"*"},
		},
	}

	router := api.SetupRoutes(nil, config)

	benchmarks := []struct {
		name   string
		method string
		path   string
	}{
		{"Health", "GET", "/health"},
		{"Version", "GET", "/api/v1/version"},
		{"ListArtifacts", "GET", "/api/v1/artifacts"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequest(bm.method, bm.path, nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					b.Fatalf("Expected status 200, got %d", w.Code)
				}
			}
		})
	}
}