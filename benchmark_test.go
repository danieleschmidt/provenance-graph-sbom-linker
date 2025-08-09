package main

import (
	"context"
	"testing"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/worker"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/google/uuid"
)

// Skip cache benchmarks for now as they require Redis connection

// Benchmark worker pool operations
func BenchmarkWorkerPoolSubmit(b *testing.B) {
	pool := worker.NewWorkerPool(4, 1000)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop(ctx)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		job := worker.NewBasicJob(
			"benchmark-job-"+string(rune(i)),
			func(ctx context.Context) error {
				time.Sleep(time.Microsecond) // Simulate work
				return nil
			},
		)
		pool.Submit(job)
	}
}

func BenchmarkWorkerPoolProcessing(b *testing.B) {
	pool := worker.NewWorkerPool(4, 1000)
	ctx := context.Background()
	pool.Start(ctx)
	defer pool.Stop(ctx)
	
	jobs := make([]*worker.BasicJob, b.N)
	for i := 0; i < b.N; i++ {
		jobs[i] = worker.NewBasicJob(
			"benchmark-job-"+string(rune(i)),
			func(ctx context.Context) error {
				// Minimal work to measure processing overhead
				return nil
			},
		)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(jobs[i])
	}
	
	// Wait for all jobs to complete
	processed := 0
	results := pool.Results()
	for processed < b.N {
		<-results
		processed++
	}
}

// Benchmark metrics collection
func BenchmarkMetricsCollectorRecordCounter(b *testing.B) {
	collector := monitoring.NewMetricsCollector(time.Second)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordCounter("benchmark_counter", 1, map[string]string{
			"test": "true",
		})
	}
}

func BenchmarkMetricsCollectorRecordGauge(b *testing.B) {
	collector := monitoring.NewMetricsCollector(time.Second)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordGauge("benchmark_gauge", float64(i), map[string]string{
			"test": "true",
		})
	}
}

func BenchmarkMetricsCollectorRecordTiming(b *testing.B) {
	collector := monitoring.NewMetricsCollector(time.Second)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordTiming("benchmark_timing", time.Millisecond, map[string]string{
			"test": "true",
		})
	}
}

// Benchmark artifact creation and validation
func BenchmarkArtifactCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		artifact := types.Artifact{
			ID:        uuid.New(),
			Name:      "benchmark-artifact",
			Version:   "1.0.0",
			Type:      types.ArtifactTypeContainer,
			Hash:      "sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata:  make(map[string]string),
		}
		_ = artifact
	}
}

func BenchmarkSBOMCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sbom := types.SBOM{
			ID:        uuid.New(),
			Format:    types.SBOMFormatCycloneDX,
			Version:   "1.0",
			CreatedAt: time.Now(),
			CreatedBy: "benchmark",
			Hash:      "sha256:test-hash",
			Metadata:  make(map[string]string),
			Components: []types.Component{
				{
					ID:          uuid.New(),
					Name:        "test-component",
					Version:     "1.0.0",
					Type:        types.ComponentTypeLibrary,
					License:     []string{"MIT"},
					Description: "Test component",
					Metadata:    make(map[string]string),
				},
			},
		}
		_ = sbom
	}
}

// Memory allocation benchmarks
func BenchmarkMemoryAllocation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Test memory allocation patterns
		data := make(map[string]interface{})
		data["key1"] = "value1"
		data["key2"] = 12345
		data["key3"] = true
		data["key4"] = time.Now()
		_ = data
	}
}

func BenchmarkSliceOperations(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		slice := make([]string, 0, 100)
		for j := 0; j < 100; j++ {
			slice = append(slice, "item-"+string(rune(j)))
		}
		_ = slice
	}
}