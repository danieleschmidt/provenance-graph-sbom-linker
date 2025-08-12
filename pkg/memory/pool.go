package memory

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// PoolConfig holds configuration for memory pools
type PoolConfig struct {
	InitialSize     int           `json:"initial_size"`
	MaxSize         int           `json:"max_size"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	MaxAge          time.Duration `json:"max_age"`
	EnableMetrics   bool          `json:"enable_metrics"`
}

// DefaultPoolConfig returns sensible defaults for memory pooling
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		InitialSize:     10,
		MaxSize:         1000,
		CleanupInterval: 5 * time.Minute,
		MaxAge:          10 * time.Minute,
		EnableMetrics:   true,
	}
}

// PoolMetrics tracks memory pool performance
type PoolMetrics struct {
	Gets        int64 `json:"gets"`
	Puts        int64 `json:"puts"`
	Hits        int64 `json:"hits"`
	Misses      int64 `json:"misses"`
	Creates     int64 `json:"creates"`
	Destroys    int64 `json:"destroys"`
	CurrentSize int64 `json:"current_size"`
	MaxReached  int64 `json:"max_reached"`
}

// HitRate calculates the cache hit rate
func (m *PoolMetrics) HitRate() float64 {
	total := m.Gets
	if total == 0 {
		return 0
	}
	return float64(m.Hits) / float64(total)
}

// poolItem represents an item in the memory pool
type poolItem struct {
	value     interface{}
	createdAt time.Time
	lastUsed  time.Time
}

// MemoryPool is a generic memory pool for object reuse
type MemoryPool struct {
	config     PoolConfig
	items      chan *poolItem
	metrics    *PoolMetrics
	createFunc func() interface{}
	resetFunc  func(interface{})
	stopCh     chan struct{}
	once       sync.Once
	mu         sync.RWMutex
}

// NewMemoryPool creates a new memory pool
func NewMemoryPool(config PoolConfig, createFunc func() interface{}, resetFunc func(interface{})) *MemoryPool {
	pool := &MemoryPool{
		config:     config,
		items:      make(chan *poolItem, config.MaxSize),
		metrics:    &PoolMetrics{},
		createFunc: createFunc,
		resetFunc:  resetFunc,
		stopCh:     make(chan struct{}),
	}

	// Pre-populate with initial items
	for i := 0; i < config.InitialSize; i++ {
		item := &poolItem{
			value:     createFunc(),
			createdAt: time.Now(),
			lastUsed:  time.Now(),
		}
		select {
		case pool.items <- item:
			atomic.AddInt64(&pool.metrics.CurrentSize, 1)
			atomic.AddInt64(&pool.metrics.Creates, 1)
		default:
			break
		}
	}

	// Start cleanup goroutine
	if config.CleanupInterval > 0 {
		go pool.cleanupLoop()
	}

	return pool
}

// Get retrieves an object from the pool
func (p *MemoryPool) Get() interface{} {
	atomic.AddInt64(&p.metrics.Gets, 1)

	select {
	case item := <-p.items:
		atomic.AddInt64(&p.metrics.CurrentSize, -1)
		atomic.AddInt64(&p.metrics.Hits, 1)
		
		item.lastUsed = time.Now()
		if p.resetFunc != nil {
			p.resetFunc(item.value)
		}
		return item.value
		
	default:
		// Pool is empty, create new object
		atomic.AddInt64(&p.metrics.Misses, 1)
		atomic.AddInt64(&p.metrics.Creates, 1)
		return p.createFunc()
	}
}

// Put returns an object to the pool
func (p *MemoryPool) Put(obj interface{}) {
	if obj == nil {
		return
	}

	atomic.AddInt64(&p.metrics.Puts, 1)

	item := &poolItem{
		value:     obj,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	select {
	case p.items <- item:
		currentSize := atomic.AddInt64(&p.metrics.CurrentSize, 1)
		// Update max reached if necessary
		for {
			maxReached := atomic.LoadInt64(&p.metrics.MaxReached)
			if currentSize <= maxReached || atomic.CompareAndSwapInt64(&p.metrics.MaxReached, maxReached, currentSize) {
				break
			}
		}
	default:
		// Pool is full, object will be garbage collected
		atomic.AddInt64(&p.metrics.Destroys, 1)
	}
}

// GetMetrics returns current pool metrics
func (p *MemoryPool) GetMetrics() PoolMetrics {
	return PoolMetrics{
		Gets:        atomic.LoadInt64(&p.metrics.Gets),
		Puts:        atomic.LoadInt64(&p.metrics.Puts),
		Hits:        atomic.LoadInt64(&p.metrics.Hits),
		Misses:      atomic.LoadInt64(&p.metrics.Misses),
		Creates:     atomic.LoadInt64(&p.metrics.Creates),
		Destroys:    atomic.LoadInt64(&p.metrics.Destroys),
		CurrentSize: atomic.LoadInt64(&p.metrics.CurrentSize),
		MaxReached:  atomic.LoadInt64(&p.metrics.MaxReached),
	}
}

// Close stops the memory pool and cleans up resources
func (p *MemoryPool) Close() {
	p.once.Do(func() {
		close(p.stopCh)
		
		// Drain the pool
		for {
			select {
			case <-p.items:
				atomic.AddInt64(&p.metrics.CurrentSize, -1)
				atomic.AddInt64(&p.metrics.Destroys, 1)
			default:
				return
			}
		}
	})
}

// cleanupLoop periodically removes old items from the pool
func (p *MemoryPool) cleanupLoop() {
	ticker := time.NewTicker(p.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.stopCh:
			return
		}
	}
}

// cleanup removes expired items from the pool
func (p *MemoryPool) cleanup() {
	now := time.Now()
	cutoff := now.Add(-p.config.MaxAge)
	
	// Create a temporary slice to hold items to keep
	var itemsToKeep []*poolItem
	
	// Drain the channel and check each item
	for {
		select {
		case item := <-p.items:
			if item.createdAt.After(cutoff) && item.lastUsed.After(cutoff) {
				itemsToKeep = append(itemsToKeep, item)
			} else {
				atomic.AddInt64(&p.metrics.CurrentSize, -1)
				atomic.AddInt64(&p.metrics.Destroys, 1)
			}
		default:
			// Channel is empty, put back the items we want to keep
			for _, item := range itemsToKeep {
				select {
				case p.items <- item:
				default:
					// Channel is full, drop the item
					atomic.AddInt64(&p.metrics.CurrentSize, -1)
					atomic.AddInt64(&p.metrics.Destroys, 1)
				}
			}
			return
		}
	}
}

// PoolManager manages multiple memory pools for different object types
type PoolManager struct {
	pools map[string]*MemoryPool
	mu    sync.RWMutex
}

// NewPoolManager creates a new pool manager
func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools: make(map[string]*MemoryPool),
	}
}

// CreateArtifactPool creates a memory pool for Artifact objects
func (pm *PoolManager) CreateArtifactPool(config PoolConfig) {
	pool := NewMemoryPool(
		config,
		func() interface{} {
			return &types.Artifact{
				Metadata: make(map[string]string),
			}
		},
		func(obj interface{}) {
			if artifact, ok := obj.(*types.Artifact); ok {
				// Reset artifact to zero values
				*artifact = types.Artifact{
					Metadata: make(map[string]string),
				}
			}
		},
	)
	
	pm.mu.Lock()
	pm.pools["artifact"] = pool
	pm.mu.Unlock()
}

// CreateSBOMPool creates a memory pool for SBOM objects
func (pm *PoolManager) CreateSBOMPool(config PoolConfig) {
	pool := NewMemoryPool(
		config,
		func() interface{} {
			return &types.SBOM{
				Metadata:   make(map[string]string),
				Components: make([]types.Component, 0, 10),
			}
		},
		func(obj interface{}) {
			if sbom, ok := obj.(*types.SBOM); ok {
				// Reset SBOM to zero values
				*sbom = types.SBOM{
					Metadata:   make(map[string]string),
					Components: sbom.Components[:0], // Keep underlying array but reset length
				}
			}
		},
	)
	
	pm.mu.Lock()
	pm.pools["sbom"] = pool
	pm.mu.Unlock()
}

// CreateSlicePool creates a memory pool for byte slices
func (pm *PoolManager) CreateSlicePool(config PoolConfig, size int) {
	pool := NewMemoryPool(
		config,
		func() interface{} {
			return make([]byte, 0, size)
		},
		func(obj interface{}) {
			if slice, ok := obj.([]byte); ok {
				// Reset slice length to 0 but keep capacity
				slice = slice[:0]
			}
		},
	)
	
	pm.mu.Lock()
	pm.pools["slice"] = pool
	pm.mu.Unlock()
}

// CreateMapPool creates a memory pool for string maps
func (pm *PoolManager) CreateMapPool(config PoolConfig) {
	pool := NewMemoryPool(
		config,
		func() interface{} {
			return make(map[string]string)
		},
		func(obj interface{}) {
			if m, ok := obj.(map[string]string); ok {
				// Clear the map
				for k := range m {
					delete(m, k)
				}
			}
		},
	)
	
	pm.mu.Lock()
	pm.pools["map"] = pool
	pm.mu.Unlock()
}

// GetPool retrieves a pool by name
func (pm *PoolManager) GetPool(name string) (*MemoryPool, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	pool, exists := pm.pools[name]
	return pool, exists
}

// GetArtifact gets an artifact from the artifact pool
func (pm *PoolManager) GetArtifact() *types.Artifact {
	if pool, exists := pm.GetPool("artifact"); exists {
		return pool.Get().(*types.Artifact)
	}
	return &types.Artifact{Metadata: make(map[string]string)}
}

// PutArtifact returns an artifact to the artifact pool
func (pm *PoolManager) PutArtifact(artifact *types.Artifact) {
	if pool, exists := pm.GetPool("artifact"); exists {
		pool.Put(artifact)
	}
}

// GetSBOM gets an SBOM from the SBOM pool
func (pm *PoolManager) GetSBOM() *types.SBOM {
	if pool, exists := pm.GetPool("sbom"); exists {
		return pool.Get().(*types.SBOM)
	}
	return &types.SBOM{
		Metadata:   make(map[string]string),
		Components: make([]types.Component, 0),
	}
}

// PutSBOM returns an SBOM to the SBOM pool
func (pm *PoolManager) PutSBOM(sbom *types.SBOM) {
	if pool, exists := pm.GetPool("sbom"); exists {
		pool.Put(sbom)
	}
}

// GetByteSlice gets a byte slice from the slice pool
func (pm *PoolManager) GetByteSlice() []byte {
	if pool, exists := pm.GetPool("slice"); exists {
		return pool.Get().([]byte)
	}
	return make([]byte, 0, 1024)
}

// PutByteSlice returns a byte slice to the slice pool
func (pm *PoolManager) PutByteSlice(slice []byte) {
	if pool, exists := pm.GetPool("slice"); exists {
		pool.Put(slice)
	}
}

// GetStringMap gets a string map from the map pool
func (pm *PoolManager) GetStringMap() map[string]string {
	if pool, exists := pm.GetPool("map"); exists {
		return pool.Get().(map[string]string)
	}
	return make(map[string]string)
}

// PutStringMap returns a string map to the map pool
func (pm *PoolManager) PutStringMap(m map[string]string) {
	if pool, exists := pm.GetPool("map"); exists {
		pool.Put(m)
	}
}

// GetAllMetrics returns metrics for all pools
func (pm *PoolManager) GetAllMetrics() map[string]PoolMetrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	metrics := make(map[string]PoolMetrics)
	for name, pool := range pm.pools {
		metrics[name] = pool.GetMetrics()
	}
	
	return metrics
}

// Close closes all pools managed by this manager
func (pm *PoolManager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for _, pool := range pm.pools {
		pool.Close()
	}
	
	pm.pools = make(map[string]*MemoryPool)
}

// GCStats provides garbage collection statistics
type GCStats struct {
	NumGC        uint32        `json:"num_gc"`
	PauseTotal   time.Duration `json:"pause_total"`
	PauseNs      []uint64      `json:"pause_ns"`
	LastGC       time.Time     `json:"last_gc"`
	NextGC       uint64        `json:"next_gc"`
	MemoryStats  MemoryStats   `json:"memory_stats"`
}

// MemoryStats provides memory usage statistics
type MemoryStats struct {
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Sys          uint64 `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapSys      uint64 `json:"heap_sys"`
	HeapIdle     uint64 `json:"heap_idle"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapReleased uint64 `json:"heap_released"`
	HeapObjects  uint64 `json:"heap_objects"`
	StackInuse   uint64 `json:"stack_inuse"`
	StackSys     uint64 `json:"stack_sys"`
}

// GetGCStats returns current garbage collection and memory statistics
func GetGCStats() GCStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	var gcStats runtime.GCStats
	runtime.ReadGCStats(&gcStats)
	
	return GCStats{
		NumGC:      memStats.NumGC,
		PauseTotal: gcStats.PauseTotal,
		PauseNs:    gcStats.Pause[:],
		LastGC:     time.Unix(0, int64(memStats.LastGC)),
		NextGC:     memStats.NextGC,
		MemoryStats: MemoryStats{
			Alloc:        memStats.Alloc,
			TotalAlloc:   memStats.TotalAlloc,
			Sys:          memStats.Sys,
			Lookups:      memStats.Lookups,
			Mallocs:      memStats.Mallocs,
			Frees:        memStats.Frees,
			HeapAlloc:    memStats.HeapAlloc,
			HeapSys:      memStats.HeapSys,
			HeapIdle:     memStats.HeapIdle,
			HeapInuse:    memStats.HeapInuse,
			HeapReleased: memStats.HeapReleased,
			HeapObjects:  memStats.HeapObjects,
			StackInuse:   memStats.StackInuse,
			StackSys:     memStats.StackSys,
		},
	}
}

// TriggerGC forces a garbage collection cycle
func TriggerGC() {
	runtime.GC()
}