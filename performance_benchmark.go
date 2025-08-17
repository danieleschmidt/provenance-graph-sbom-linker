package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Performance benchmark test for the Provenance Linker API
func main() {
	baseURL := "http://localhost:8080"
	
	fmt.Println("🚀 Starting Provenance Linker Performance Benchmarks")
	
	// Benchmark 1: Health Check Latency
	fmt.Println("\n📊 Benchmark 1: Health Check Latency")
	healthLatency := benchmarkHealthCheck(baseURL, 1000)
	fmt.Printf("Average latency: %.2fms\n", healthLatency)
	
	// Benchmark 2: Artifact Creation Throughput
	fmt.Println("\n📊 Benchmark 2: Artifact Creation Throughput")
	artifactThroughput := benchmarkArtifactCreation(baseURL, 100, 10)
	fmt.Printf("Throughput: %.2f requests/second\n", artifactThroughput)
	
	// Benchmark 3: SBOM Analysis Performance
	fmt.Println("\n📊 Benchmark 3: SBOM Analysis Performance")
	sbomLatency := benchmarkSBOMAnalysis(baseURL, 50)
	fmt.Printf("Average latency: %.2fms\n", sbomLatency)
	
	// Benchmark 4: Provenance Graph Query
	fmt.Println("\n📊 Benchmark 4: Provenance Graph Query")
	graphLatency := benchmarkProvenanceGraph(baseURL, 100)
	fmt.Printf("Average latency: %.2fms\n", graphLatency)
	
	// Benchmark 5: Concurrent Load Test
	fmt.Println("\n📊 Benchmark 5: Concurrent Load Test")
	loadTestResults := benchmarkConcurrentLoad(baseURL, 50, 100)
	fmt.Printf("Success rate: %.2f%%, Average latency: %.2fms\n", 
		loadTestResults.SuccessRate, loadTestResults.AvgLatency)
	
	fmt.Println("\n🎯 Performance Summary:")
	fmt.Printf("✅ Health check latency: %.2fms (target: <50ms)\n", healthLatency)
	fmt.Printf("✅ Artifact throughput: %.2f req/s (target: >50 req/s)\n", artifactThroughput)
	fmt.Printf("✅ SBOM analysis latency: %.2fms (target: <200ms)\n", sbomLatency)
	fmt.Printf("✅ Graph query latency: %.2fms (target: <100ms)\n", graphLatency)
	fmt.Printf("✅ Load test success rate: %.2f%% (target: >95%%)\n", loadTestResults.SuccessRate)
	
	// Evaluate performance
	if healthLatency < 50 && artifactThroughput > 50 && sbomLatency < 200 && 
	   graphLatency < 100 && loadTestResults.SuccessRate > 95 {
		fmt.Println("\n🏆 ALL PERFORMANCE TARGETS MET!")
	} else {
		fmt.Println("\n⚠️  Some performance targets not met")
	}
}

func benchmarkHealthCheck(baseURL string, iterations int) float64 {
	var totalLatency time.Duration
	
	for i := 0; i < iterations; i++ {
		start := time.Now()
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
		}
		totalLatency += time.Since(start)
		
		if i%100 == 0 {
			fmt.Printf(".")
		}
	}
	
	return float64(totalLatency.Nanoseconds()) / float64(iterations) / 1e6
}

func benchmarkArtifactCreation(baseURL string, concurrent, iterations int) float64 {
	var wg sync.WaitGroup
	start := time.Now()
	totalRequests := concurrent * iterations
	
	for c := 0; c < concurrent; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for i := 0; i < iterations; i++ {
				payload := map[string]interface{}{
					"name":    fmt.Sprintf("benchmark-artifact-%d", i),
					"version": "v1.0.0",
					"type":    "container",
					"hash":    fmt.Sprintf("sha256:bench%d", i),
					"size":    1024000,
				}
				
				jsonPayload, _ := json.Marshal(payload)
				resp, err := http.Post(baseURL+"/api/v1/artifacts/", "application/json", bytes.NewBuffer(jsonPayload))
				if err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	return float64(totalRequests) / duration.Seconds()
}

func benchmarkSBOMAnalysis(baseURL string, iterations int) float64 {
	sbomData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:benchmark-123",
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
			},
			{
				"type": "library",
				"name": "neo4j/neo4j-go-driver",
				"version": "v5.24.0",
				"licenses": [{"license": {"id": "Apache-2.0"}}]
			}
		]
	}`
	
	payload := map[string]interface{}{
		"sbom_data":            sbomData,
		"check_licenses":       true,
		"check_vulnerabilities": true,
	}
	
	var totalLatency time.Duration
	
	for i := 0; i < iterations; i++ {
		start := time.Now()
		jsonPayload, _ := json.Marshal(payload)
		resp, err := http.Post(baseURL+"/api/v1/sbom/analyze", "application/json", bytes.NewBuffer(jsonPayload))
		if err == nil {
			resp.Body.Close()
		}
		totalLatency += time.Since(start)
		
		if i%10 == 0 {
			fmt.Printf(".")
		}
	}
	
	return float64(totalLatency.Nanoseconds()) / float64(iterations) / 1e6
}

func benchmarkProvenanceGraph(baseURL string, iterations int) float64 {
	var totalLatency time.Duration
	
	for i := 0; i < iterations; i++ {
		start := time.Now()
		resp, err := http.Get(baseURL + "/api/v1/provenance/graph?artifact=benchmark-app:v1.0.0")
		if err == nil {
			resp.Body.Close()
		}
		totalLatency += time.Since(start)
		
		if i%10 == 0 {
			fmt.Printf(".")
		}
	}
	
	return float64(totalLatency.Nanoseconds()) / float64(iterations) / 1e6
}

type LoadTestResults struct {
	SuccessRate float64
	AvgLatency  float64
	TotalRequests int
	SuccessfulRequests int
}

func benchmarkConcurrentLoad(baseURL string, concurrent, requestsPerWorker int) LoadTestResults {
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	totalRequests := concurrent * requestsPerWorker
	successfulRequests := 0
	var totalLatency time.Duration
	
	for c := 0; c < concurrent; c++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for i := 0; i < requestsPerWorker; i++ {
				requestStart := time.Now()
				
				// Mix of different API calls
				var success bool
				switch i % 4 {
				case 0:
					// Health check
					resp, err := http.Get(baseURL + "/health")
					success = err == nil && resp.StatusCode == 200
					if resp != nil {
						resp.Body.Close()
					}
				case 1:
					// Create artifact
					payload := map[string]interface{}{
						"name":    fmt.Sprintf("load-test-%d-%d", workerID, i),
						"version": "v1.0.0",
						"type":    "container",
						"hash":    fmt.Sprintf("sha256:load%d%d", workerID, i),
						"size":    1024000,
					}
					jsonPayload, _ := json.Marshal(payload)
					resp, err := http.Post(baseURL+"/api/v1/artifacts/", "application/json", bytes.NewBuffer(jsonPayload))
					success = err == nil && resp.StatusCode == 201
					if resp != nil {
						resp.Body.Close()
					}
				case 2:
					// Provenance graph
					resp, err := http.Get(baseURL + "/api/v1/provenance/graph?artifact=load-test:v1.0.0")
					success = err == nil && resp.StatusCode == 200
					if resp != nil {
						resp.Body.Close()
					}
				case 3:
					// Metrics
					resp, err := http.Get(baseURL + "/metrics/prometheus")
					success = err == nil && resp.StatusCode == 200
					if resp != nil {
						resp.Body.Close()
					}
				}
				
				requestLatency := time.Since(requestStart)
				
				mu.Lock()
				if success {
					successfulRequests++
				}
				totalLatency += requestLatency
				mu.Unlock()
			}
		}(c)
	}
	
	wg.Wait()
	
	successRate := float64(successfulRequests) / float64(totalRequests) * 100
	avgLatency := float64(totalLatency.Nanoseconds()) / float64(totalRequests) / 1e6
	
	return LoadTestResults{
		SuccessRate:        successRate,
		AvgLatency:         avgLatency,
		TotalRequests:      totalRequests,
		SuccessfulRequests: successfulRequests,
	}
}