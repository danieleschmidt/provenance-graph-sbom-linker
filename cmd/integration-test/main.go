package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Integration test suite for the Provenance Linker API
func main() {
	baseURL := "http://localhost:8080"
	
	fmt.Println("🚀 Starting Provenance Linker Integration Tests")
	
	// Test 1: Health Check
	fmt.Print("✅ Testing health endpoint... ")
	if testHealthCheck(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 2: Create Artifact
	fmt.Print("✅ Testing artifact creation... ")
	artifactID := testCreateArtifact(baseURL)
	if artifactID != "" {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 3: Get Artifact
	fmt.Print("✅ Testing artifact retrieval... ")
	if testGetArtifact(baseURL, artifactID) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 4: Track Build
	fmt.Print("✅ Testing build tracking... ")
	if testTrackBuild(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 5: SBOM Analysis
	fmt.Print("✅ Testing SBOM analysis... ")
	if testSBOMAnalysis(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 6: Compliance Report
	fmt.Print("✅ Testing compliance reporting... ")
	if testComplianceReport(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 7: Signature Verification
	fmt.Print("✅ Testing signature verification... ")
	if testSignatureVerification(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 8: Provenance Graph
	fmt.Print("✅ Testing provenance graph... ")
	if testProvenanceGraph(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	// Test 9: Metrics
	fmt.Print("✅ Testing metrics endpoint... ")
	if testMetrics(baseURL) {
		fmt.Println("PASSED")
	} else {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	
	fmt.Println("\n🎉 All integration tests passed!")
	fmt.Println("✨ Provenance Linker API is fully operational")
}

func testHealthCheck(baseURL string) bool {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false
	}
	
	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	
	return health["status"] == "healthy"
}

func testCreateArtifact(baseURL string) string {
	payload := map[string]interface{}{
		"name":    "test-artifact",
		"version": "v1.0.0",
		"type":    "container",
		"hash":    "sha256:abcd1234",
		"size":    1024000,
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/api/v1/artifacts/", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusCreated {
		return ""
	}
	
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	if id, ok := result["id"].(string); ok {
		return id
	}
	
	return ""
}

func testGetArtifact(baseURL, artifactID string) bool {
	resp, err := http.Get(baseURL + "/api/v1/artifacts/" + artifactID)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func testTrackBuild(baseURL string) bool {
	payload := map[string]interface{}{
		"source_ref":   "github.com/org/repo",
		"commit_hash":  "abc123def456",
		"build_system": "github-actions",
		"build_url":    "https://github.com/org/repo/actions/runs/123",
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/api/v1/provenance/track", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusCreated
}

func testSBOMAnalysis(baseURL string) bool {
	sbomData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:test-123",
		"version": 1,
		"metadata": {
			"timestamp": "2025-08-17T01:30:00Z",
			"tools": [{"vendor": "CycloneDX", "name": "cyclonedx-cli", "version": "0.24.0"}]
		},
		"components": [
			{
				"type": "library",
				"name": "gin-gonic/gin",
				"version": "v1.10.1",
				"licenses": [{"license": {"id": "MIT"}}]
			}
		]
	}`
	
	payload := map[string]interface{}{
		"sbom_data":            sbomData,
		"check_licenses":       true,
		"check_vulnerabilities": true,
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/api/v1/sbom/analyze", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func testComplianceReport(baseURL string) bool {
	payload := map[string]interface{}{
		"standard":     "nist-ssdf-v1.1",
		"project_name": "test-project",
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/api/v1/compliance/reports", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusCreated
}

func testSignatureVerification(baseURL string) bool {
	payload := map[string]interface{}{
		"artifact_uri": "docker.io/myorg/myapp:v1.0.0",
		"public_key":   "cosign.pub",
	}
	
	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(baseURL+"/api/v1/signatures/verify", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func testProvenanceGraph(baseURL string) bool {
	resp, err := http.Get(baseURL + "/api/v1/provenance/graph?artifact=my-app:v1.0.0")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

func testMetrics(baseURL string) bool {
	resp, err := http.Get(baseURL + "/metrics/prometheus")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	
	// Check for expected metrics
	bodyStr := string(body)
	return bytes.Contains([]byte(bodyStr), []byte("provenance_requests_total")) &&
		   bytes.Contains([]byte(bodyStr), []byte("provenance_artifacts_total"))
}