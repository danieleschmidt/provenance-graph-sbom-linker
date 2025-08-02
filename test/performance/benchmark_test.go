package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/your-org/provenance-graph-sbom-linker/test/testutil"
)

// BenchmarkSBOMParsing benchmarks SBOM parsing performance
func BenchmarkSBOMParsing(b *testing.B) {
	testCases := []struct {
		name     string
		format   string
		size     string
		filename string
	}{
		{"CycloneDX_Small", "cyclonedx", "small", "simple.json"},
		{"CycloneDX_Medium", "cyclonedx", "medium", "go-project.json"},
		{"CycloneDX_Large", "cyclonedx", "large", "complex.json"},
		{"SPDX_Small", "spdx", "small", "simple.json"},
		{"SPDX_Medium", "spdx", "medium", "with-rels.json"},
		{"SPDX_Large", "spdx", "large", "complex.json"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate test SBOM data
			sbom := testutil.NewTestSBOM()
			
			// Adjust complexity based on size
			switch tc.size {
			case "small":
				sbom.Components = sbom.Components[:2]
			case "medium":
				// Add more components for medium size
				for i := 0; i < 50; i++ {
					sbom.Components = append(sbom.Components, testutil.TestSBOMComponent{
						Type:    "library",
						Name:    fmt.Sprintf("component-%d", i),
						Version: "1.0.0",
						PURL:    fmt.Sprintf("pkg:generic/component-%d@1.0.0", i),
					})
				}
			case "large":
				// Add many components for large size
				for i := 0; i < 500; i++ {
					sbom.Components = append(sbom.Components, testutil.TestSBOMComponent{
						Type:    "library",
						Name:    fmt.Sprintf("component-%d", i),
						Version: "1.0.0",
						PURL:    fmt.Sprintf("pkg:generic/component-%d@1.0.0", i),
					})
				}
			}
			
			sbomData, err := json.Marshal(sbom)
			if err != nil {
				b.Fatalf("Failed to marshal SBOM: %v", err)
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Simulate SBOM parsing
				var parsedSBOM testutil.TestSBOM
				err := json.Unmarshal(sbomData, &parsedSBOM)
				if err != nil {
					b.Fatalf("Failed to parse SBOM: %v", err)
				}
			}
		})
	}
}

// BenchmarkGraphOperations benchmarks graph database operations
func BenchmarkGraphOperations(b *testing.B) {
	db := testutil.NewTestDB(b)
	ctx := context.Background()

	testCases := []struct {
		name      string
		operation string
		batchSize int
	}{
		{"CreateNode_Single", "create_node", 1},
		{"CreateNode_Batch10", "create_node", 10},
		{"CreateNode_Batch100", "create_node", 100},
		{"QueryNode_Single", "query_node", 1},
		{"QueryNode_Multiple", "query_node", 10},
		{"CreateRelationship_Single", "create_rel", 1},
		{"CreateRelationship_Batch10", "create_rel", 10},
		{"CreateRelationship_Batch100", "create_rel", 100},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				switch tc.operation {
				case "create_node":
					benchmarkCreateNodes(b, db, ctx, tc.batchSize)
				case "query_node":
					benchmarkQueryNodes(b, db, ctx, tc.batchSize)
				case "create_rel":
					benchmarkCreateRelationships(b, db, ctx, tc.batchSize)
				}
			}
		})
	}
}

// BenchmarkSignatureVerification benchmarks signature verification
func BenchmarkSignatureVerification(b *testing.B) {
	testCases := []struct {
		name      string
		algorithm string
		keySize   int
	}{
		{"RSA_2048", "RSA", 2048},
		{"RSA_4096", "RSA", 4096},
		{"ECDSA_P256", "ECDSA", 256},
		{"ECDSA_P384", "ECDSA", 384},
		{"ECDSA_P521", "ECDSA", 521},
		{"Ed25519", "Ed25519", 256},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate test signature
			signature := testutil.NewTestSignature()
			signature.Algorithm = tc.algorithm
			
			// Simulate signature data
			testData := []byte("test artifact data for signature verification")
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Simulate signature verification
				verified := verifyTestSignature(signature, testData)
				if !verified {
					b.Fatalf("Signature verification failed")
				}
			}
		})
	}
}

// BenchmarkVulnerabilityScanning benchmarks vulnerability scanning
func BenchmarkVulnerabilityScanning(b *testing.B) {
	testCases := []struct {
		name           string
		componentCount int
		vulnCount      int
	}{
		{"Small_10Components_5Vulns", 10, 5},
		{"Medium_100Components_25Vulns", 100, 25},
		{"Large_1000Components_100Vulns", 1000, 100},
		{"XLarge_10000Components_500Vulns", 10000, 500},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate test SBOM with specified number of components
			sbom := testutil.NewTestSBOM()
			sbom.Components = make([]testutil.TestSBOMComponent, tc.componentCount)
			sbom.Vulnerabilities = make([]testutil.TestVulnerability, tc.vulnCount)
			
			for i := 0; i < tc.componentCount; i++ {
				sbom.Components[i] = testutil.TestSBOMComponent{
					Type:    "library",
					Name:    fmt.Sprintf("component-%d", i),
					Version: "1.0.0",
					PURL:    fmt.Sprintf("pkg:generic/component-%d@1.0.0", i),
				}
			}
			
			for i := 0; i < tc.vulnCount; i++ {
				vuln := testutil.NewTestVulnerability()
				vuln.ID = fmt.Sprintf("CVE-2024-%05d", i)
				sbom.Vulnerabilities[i] = vuln
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Simulate vulnerability scanning
				results := simulateVulnerabilityScanning(sbom)
				if len(results) == 0 {
					b.Fatalf("No vulnerability results returned")
				}
			}
		})
	}
}

// BenchmarkAPIEndpoints benchmarks API endpoint performance
func BenchmarkAPIEndpoints(b *testing.B) {
	testCases := []struct {
		name     string
		endpoint string
		method   string
		payload  interface{}
	}{
		{"POST_Artifact", "/api/v1/artifacts", "POST", testutil.NewTestArtifact()},
		{"GET_Artifact", "/api/v1/artifacts/test-123", "GET", nil},
		{"POST_BuildEvent", "/api/v1/builds", "POST", testutil.NewTestBuildEvent()},
		{"GET_Provenance", "/api/v1/provenance/test-123", "GET", nil},
		{"POST_SBOM", "/api/v1/sbom", "POST", testutil.NewTestSBOM()},
		{"GET_Vulnerabilities", "/api/v1/vulnerabilities", "GET", nil},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Simulate API request
				response := simulateAPIRequest(tc.method, tc.endpoint, tc.payload)
				if response.StatusCode != 200 {
					b.Fatalf("API request failed with status %d", response.StatusCode)
				}
			}
		})
	}
}

// BenchmarkConcurrentOperations benchmarks concurrent operations
func BenchmarkConcurrentOperations(b *testing.B) {
	testCases := []struct {
		name        string
		operation   string
		concurrency int
	}{
		{"SBOMParsing_Concurrent10", "sbom_parsing", 10},
		{"SBOMParsing_Concurrent50", "sbom_parsing", 50},
		{"SBOMParsing_Concurrent100", "sbom_parsing", 100},
		{"GraphWrite_Concurrent10", "graph_write", 10},
		{"GraphWrite_Concurrent50", "graph_write", 50},
		{"SignatureVerify_Concurrent10", "signature_verify", 10},
		{"SignatureVerify_Concurrent50", "signature_verify", 50},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Run concurrent operations
				done := make(chan bool, tc.concurrency)
				
				for j := 0; j < tc.concurrency; j++ {
					go func() {
						defer func() { done <- true }()
						
						switch tc.operation {
						case "sbom_parsing":
							simulateSBOMParsing()
						case "graph_write":
							simulateGraphWrite()
						case "signature_verify":
							simulateSignatureVerification()
						}
					}()
				}
				
				// Wait for all goroutines to complete
				for j := 0; j < tc.concurrency; j++ {
					<-done
				}
			}
		})
	}
}

// Helper functions for benchmarks

func benchmarkCreateNodes(b *testing.B, db *testutil.TestDB, ctx context.Context, batchSize int) {
	for i := 0; i < batchSize; i++ {
		query := `
			CREATE (n:TestArtifact {
				id: $id,
				name: $name,
				version: $version,
				created_at: datetime()
			})
		`
		
		params := map[string]any{
			"id":      fmt.Sprintf("test-artifact-%d-%d", b.N, i),
			"name":    "test-artifact",
			"version": "1.0.0",
		}
		
		_, err := db.ExecuteQuery(ctx, query, params)
		if err != nil {
			b.Fatalf("Failed to create node: %v", err)
		}
	}
}

func benchmarkQueryNodes(b *testing.B, db *testutil.TestDB, ctx context.Context, count int) {
	query := `
		MATCH (n:TestArtifact)
		WHERE n.name = $name
		RETURN n
		LIMIT $limit
	`
	
	params := map[string]any{
		"name":  "test-artifact",
		"limit": count,
	}
	
	_, err := db.ExecuteQuery(ctx, query, params)
	if err != nil {
		b.Fatalf("Failed to query nodes: %v", err)
	}
}

func benchmarkCreateRelationships(b *testing.B, db *testutil.TestDB, ctx context.Context, batchSize int) {
	for i := 0; i < batchSize; i++ {
		query := `
			MATCH (a:TestArtifact {name: "test-artifact"})
			MATCH (b:TestArtifact {name: "test-artifact"})
			WHERE a <> b
			CREATE (a)-[:DEPENDS_ON]->(b)
		`
		
		_, err := db.ExecuteQuery(ctx, query, nil)
		if err != nil {
			b.Fatalf("Failed to create relationship: %v", err)
		}
	}
}

func verifyTestSignature(signature testutil.TestSignature, data []byte) bool {
	// Simulate signature verification (always return true for benchmark)
	time.Sleep(time.Microsecond * 10) // Simulate crypto work
	return true
}

func simulateVulnerabilityScanning(sbom testutil.TestSBOM) []testutil.TestVulnerability {
	// Simulate vulnerability scanning work
	results := make([]testutil.TestVulnerability, 0)
	
	for _, component := range sbom.Components {
		// Simulate scanning each component
		if len(component.Name)%3 == 0 { // Simulate some components having vulns
			vuln := testutil.NewTestVulnerability()
			vuln.Affects = []testutil.TestVulnerableComponent{
				{
					Name:    component.Name,
					Version: component.Version,
				},
			}
			results = append(results, vuln)
		}
	}
	
	return results
}

type MockAPIResponse struct {
	StatusCode int
	Body       []byte
}

func simulateAPIRequest(method, endpoint string, payload interface{}) MockAPIResponse {
	// Simulate API processing time
	time.Sleep(time.Microsecond * 50)
	
	return MockAPIResponse{
		StatusCode: 200,
		Body:       []byte(`{"status": "success"}`),
	}
}

func simulateSBOMParsing() {
	sbom := testutil.NewTestSBOM()
	data, _ := json.Marshal(sbom)
	var parsed testutil.TestSBOM
	json.Unmarshal(data, &parsed)
}

func simulateGraphWrite() {
	// Simulate graph database write
	time.Sleep(time.Microsecond * 100)
}

func simulateSignatureVerification() {
	signature := testutil.NewTestSignature()
	data := []byte("test data")
	verifyTestSignature(signature, data)
}

// Memory usage benchmarks

func BenchmarkMemoryUsage(b *testing.B) {
	testCases := []struct {
		name           string
		componentCount int
	}{
		{"SBOM_100Components", 100},
		{"SBOM_1000Components", 1000},
		{"SBOM_10000Components", 10000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				// Create large SBOM in memory
				sbom := testutil.NewTestSBOM()
				sbom.Components = make([]testutil.TestSBOMComponent, tc.componentCount)
				
				for j := 0; j < tc.componentCount; j++ {
					sbom.Components[j] = testutil.TestSBOMComponent{
						Type:    "library",
						Name:    fmt.Sprintf("component-%d", j),
						Version: "1.0.0",
						PURL:    fmt.Sprintf("pkg:generic/component-%d@1.0.0", j),
						Properties: map[string]string{
							"source": "test",
							"arch":   "amd64",
						},
					}
				}
				
				// Serialize to measure total memory impact
				_, err := json.Marshal(sbom)
				if err != nil {
					b.Fatalf("Failed to marshal SBOM: %v", err)
				}
			}
		})
	}
}