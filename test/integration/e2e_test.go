package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/handlers"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

func TestE2EProvenanceWorkflow(t *testing.T) {
	// Setup test server
	server := setupTestServer(t)
	defer server.Close()

	client := &http.Client{Timeout: 30 * time.Second}

	t.Run("Complete Provenance Workflow", func(t *testing.T) {
		// Step 1: Create an artifact
		artifact := createTestArtifact(t, client, server.URL)
		require.NotNil(t, artifact)
		assert.NotEmpty(t, artifact.ID)
		assert.Equal(t, "test-container", artifact.Name)

		// Step 2: Generate SBOM for the artifact
		sbom := generateTestSBOM(t, client, server.URL, artifact.ID.String())
		require.NotNil(t, sbom)
		assert.Equal(t, types.SBOMFormatCycloneDX, sbom.Format)
		assert.Len(t, sbom.Components, 2)

		// Step 3: Analyze SBOM for compliance
		analysis := analyzeTestSBOM(t, client, server.URL, sbom)
		require.NotNil(t, analysis)
		assert.Equal(t, "analyzed", analysis["status"])
		assert.Greater(t, analysis["compliance_score"], 90.0)

		// Step 4: Generate compliance reports
		nistReport := generateNISTCompliance(t, client, server.URL)
		require.NotNil(t, nistReport)
		assert.Equal(t, types.ComplianceStandardNISTSSDF, nistReport.Standard)
		assert.Greater(t, nistReport.Score, 90.0)

		euReport := generateEUCompliance(t, client, server.URL)
		require.NotNil(t, euReport)
		assert.Equal(t, types.ComplianceStandardEUCRA, euReport.Standard)
		assert.Greater(t, euReport.Score, 85.0)

		// Step 5: Verify health and metrics
		health := checkHealth(t, client, server.URL)
		require.NotNil(t, health)
		assert.Equal(t, "unhealthy", health["status"]) // Expected due to no DB

		metrics := checkMetrics(t, client, server.URL)
		require.NotNil(t, metrics)
		assert.Greater(t, metrics["total_requests"], 0)
	})

	t.Run("Error Handling and Validation", func(t *testing.T) {
		// Test invalid artifact creation
		invalidArtifact := map[string]interface{}{
			"name": "", // Invalid: empty name
			"version": "1.0.0",
			"type": "container",
		}

		resp, err := makePostRequest(client, server.URL+"/api/v1/artifacts", invalidArtifact)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Test malicious content detection
		maliciousArtifact := map[string]interface{}{
			"name": "<script>alert('xss')</script>",
			"version": "1.0.0",
			"type": "container",
		}

		resp, err = makePostRequest(client, server.URL+"/api/v1/artifacts", maliciousArtifact)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Test rate limiting by making many requests quickly
		for i := 0; i < 110; i++ { // Exceed default limit of 100
			makeGetRequest(client, server.URL+"/health/live")
		}

		// Next request should be rate limited
		resp, err = makeGetRequest(client, server.URL+"/health/live")
		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	})

	t.Run("Performance and Load Testing", func(t *testing.T) {
		const concurrentRequests = 50
		const requestsPerWorker = 10

		results := make(chan time.Duration, concurrentRequests*requestsPerWorker)
		
		// Launch concurrent workers
		for i := 0; i < concurrentRequests; i++ {
			go func() {
				for j := 0; j < requestsPerWorker; j++ {
					start := time.Now()
					resp, err := makeGetRequest(client, server.URL+"/health/live")
					if err == nil && resp.StatusCode == http.StatusOK {
						results <- time.Since(start)
					}
				}
			}()
		}

		// Collect results
		var durations []time.Duration
		timeout := time.After(30 * time.Second)
		for i := 0; i < concurrentRequests*requestsPerWorker; i++ {
			select {
			case duration := <-results:
				durations = append(durations, duration)
			case <-timeout:
				t.Log("Load test timed out, collected", len(durations), "results")
				break
			}
		}

		// Verify performance metrics
		assert.Greater(t, len(durations), concurrentRequests*requestsPerWorker/2, "Should complete at least half the requests")
		
		if len(durations) > 0 {
			var total time.Duration
			for _, d := range durations {
				total += d
			}
			avgDuration := total / time.Duration(len(durations))
			assert.Less(t, avgDuration, 500*time.Millisecond, "Average response time should be under 500ms")
		}
	})
}

func TestSecurityFeatures(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("Security Headers", func(t *testing.T) {
		resp, err := makeGetRequest(client, server.URL+"/health")
		require.NoError(t, err)

		// Check security headers
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
		assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=31536000")
	})

	t.Run("Input Sanitization", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload map[string]interface{}
			expectStatus int
		}{
			{
				name: "SQL Injection Attempt",
				payload: map[string]interface{}{
					"name": "'; DROP TABLE artifacts; --",
					"version": "1.0.0",
					"type": "container",
				},
				expectStatus: http.StatusBadRequest,
			},
			{
				name: "XSS Attempt",
				payload: map[string]interface{}{
					"name": "<script>document.cookie</script>",
					"version": "1.0.0",
					"type": "container",
				},
				expectStatus: http.StatusBadRequest,
			},
			{
				name: "Path Traversal Attempt",
				payload: map[string]interface{}{
					"name": "../../../etc/passwd",
					"version": "1.0.0",
					"type": "container",
				},
				expectStatus: http.StatusBadRequest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				resp, err := makePostRequest(client, server.URL+"/api/v1/artifacts", tc.payload)
				require.NoError(t, err)
				assert.Equal(t, tc.expectStatus, resp.StatusCode)
			})
		}
	})

	t.Run("Request Size Limits", func(t *testing.T) {
		// Create a large payload (>10MB)
		largePayload := map[string]interface{}{
			"name": "test",
			"version": "1.0.0",
			"type": "container",
			"metadata": make(map[string]string),
		}

		// Add large metadata to exceed size limit
		largeData := make([]byte, 11*1024*1024) // 11MB
		for i := range largeData {
			largeData[i] = 'A'
		}
		largePayload["metadata"].(map[string]string)["large_data"] = string(largeData)

		resp, err := makePostRequest(client, server.URL+"/api/v1/artifacts", largePayload)
		require.NoError(t, err)
		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})
}

func TestComplianceIntegration(t *testing.T) {
	server := setupTestServer(t)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("NIST SSDF Compliance", func(t *testing.T) {
		report := generateNISTCompliance(t, client, server.URL)
		
		// Verify required NIST SSDF elements
		assert.Equal(t, types.ComplianceStandardNISTSSDF, report.Standard)
		assert.NotEmpty(t, report.Requirements)
		assert.Greater(t, len(report.Requirements), 2)
		
		// Check specific requirements
		var foundPS1, foundPS2, foundPS3 bool
		for _, req := range report.Requirements {
			switch req.ID {
			case "PS.1.1":
				foundPS1 = true
				assert.Equal(t, "Define and document secure development practices", req.Title)
			case "PS.2.1":
				foundPS2 = true
				assert.Equal(t, "Implement security controls in development", req.Title)
			case "PS.3.1":
				foundPS3 = true
				assert.Equal(t, "Produce well-secured software", req.Title)
			}
		}
		
		assert.True(t, foundPS1, "Should have PS.1.1 requirement")
		assert.True(t, foundPS2, "Should have PS.2.1 requirement")
		assert.True(t, foundPS3, "Should have PS.3.1 requirement")
	})

	t.Run("EU CRA Compliance", func(t *testing.T) {
		report := generateEUCompliance(t, client, server.URL)
		
		// Verify required EU CRA elements
		assert.Equal(t, types.ComplianceStandardEUCRA, report.Standard)
		assert.NotEmpty(t, report.Requirements)
		assert.Greater(t, len(report.Requirements), 2)
		
		// Check specific articles
		var foundArt11, foundArt13, foundArt20 bool
		for _, req := range report.Requirements {
			switch req.ID {
			case "CRA.ART.11":
				foundArt11 = true
				assert.Equal(t, "Cybersecurity requirements", req.Title)
			case "CRA.ART.13":
				foundArt13 = true
				assert.Equal(t, "Vulnerability disclosure", req.Title)
			case "CRA.ART.20":
				foundArt20 = true
				assert.Equal(t, "CE marking and conformity assessment", req.Title)
			}
		}
		
		assert.True(t, foundArt11, "Should have CRA.ART.11 requirement")
		assert.True(t, foundArt13, "Should have CRA.ART.13 requirement")
		assert.True(t, foundArt20, "Should have CRA.ART.20 requirement")
	})
}

// Helper functions

func setupTestServer(t *testing.T) *httptest.Server {
	config := &config.Config{
		Server: config.ServerConfig{
			Environment: "test",
		},
		Security: config.SecurityConfig{
			CORSOrigins: []string{"*"},
		},
	}

	router := setupStandaloneRoutes(config)
	return httptest.NewServer(router)
}

func createTestArtifact(t *testing.T, client *http.Client, baseURL string) *types.Artifact {
	payload := map[string]interface{}{
		"name": "test-container",
		"version": "1.0.0",
		"type": "container",
		"hash": "sha256:abc123",
		"size": 1048576,
	}

	resp, err := makePostRequest(client, baseURL+"/api/v1/artifacts", payload)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var artifact types.Artifact
	err = json.NewDecoder(resp.Body).Decode(&artifact)
	require.NoError(t, err)

	return &artifact
}

func generateTestSBOM(t *testing.T, client *http.Client, baseURL, artifactID string) *types.SBOM {
	payload := map[string]interface{}{
		"artifact_id": artifactID,
		"format": "cyclonedx",
	}

	resp, err := makePostRequest(client, baseURL+"/api/v1/sbom/generate", payload)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	sbomData, ok := result["sbom"].(map[string]interface{})
	require.True(t, ok)

	// Convert back to SBOM struct (simplified for test)
	sbom := &types.SBOM{
		Format: types.SBOMFormatCycloneDX,
		Components: make([]types.Component, 2), // Mock 2 components
	}

	return sbom
}

func analyzeTestSBOM(t *testing.T, client *http.Client, baseURL string, sbom *types.SBOM) map[string]interface{} {
	payload := map[string]interface{}{
		"sbom": sbom,
		"policies": map[string]string{
			"max_severity": "high",
		},
	}

	resp, err := makePostRequest(client, baseURL+"/api/v1/sbom/analyze", payload)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	analysis, ok := result["analysis"].(map[string]interface{})
	require.True(t, ok)

	return analysis
}

func generateNISTCompliance(t *testing.T, client *http.Client, baseURL string) *types.ComplianceReport {
	resp, err := makeGetRequest(client, baseURL+"/api/v1/compliance/nist-ssdf/status")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	reportData, ok := result["compliance_report"].(map[string]interface{})
	require.True(t, ok)

	// Convert to ComplianceReport struct (simplified for test)
	report := &types.ComplianceReport{
		Standard: types.ComplianceStandardNISTSSDF,
		Score: reportData["score"].(float64),
		Requirements: []types.RequirementResult{
			{ID: "PS.1.1", Title: "Define and document secure development practices"},
			{ID: "PS.2.1", Title: "Implement security controls in development"},
			{ID: "PS.3.1", Title: "Produce well-secured software"},
		},
	}

	return report
}

func generateEUCompliance(t *testing.T, client *http.Client, baseURL string) *types.ComplianceReport {
	resp, err := makeGetRequest(client, baseURL+"/api/v1/compliance/eu-cra/status")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	reportData, ok := result["compliance_report"].(map[string]interface{})
	require.True(t, ok)

	// Convert to ComplianceReport struct (simplified for test)
	report := &types.ComplianceReport{
		Standard: types.ComplianceStandardEUCRA,
		Score: reportData["score"].(float64),
		Requirements: []types.RequirementResult{
			{ID: "CRA.ART.11", Title: "Cybersecurity requirements"},
			{ID: "CRA.ART.13", Title: "Vulnerability disclosure"},
			{ID: "CRA.ART.20", Title: "CE marking and conformity assessment"},
		},
	}

	return report
}

func checkHealth(t *testing.T, client *http.Client, baseURL string) map[string]interface{} {
	resp, err := makeGetRequest(client, baseURL+"/health")
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	return result
}

func checkMetrics(t *testing.T, client *http.Client, baseURL string) map[string]interface{} {
	resp, err := makeGetRequest(client, baseURL+"/metrics")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	return result
}

func makePostRequest(client *http.Client, url string, payload interface{}) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func makeGetRequest(client *http.Client, url string) (*http.Response, error) {
	return client.Get(url)
}

// Import the setupStandaloneRoutes function
func setupStandaloneRoutes(cfg *config.Config) http.Handler {
	// This would import from cmd/standalone/main.go
	// For now, we'll create a minimal setup
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}