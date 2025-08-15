package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// PerformanceCache provides intelligent multi-level caching with predictive preloading
type PerformanceCache struct {
	redis                *redis.Client
	localCache          *LocalCache
	config              CacheConfig
	logger              *logger.StructuredLogger
	metricsCollector    *monitoring.MetricsCollector
	preloadingEngine    *PreloadingEngine
	partitionManager    *PartitionManager
	compressionEngine   *CompressionEngine
	hotKeyDetector      *HotKeyDetector
	started             bool
	stopCh              chan bool
	mutex               sync.RWMutex
}

type CacheConfig struct {
	RedisAddress         string
	RedisPassword        string
	RedisDB             int
	LocalCacheSize      int
	DefaultTTL          time.Duration
	PreloadingEnabled   bool
	CompressionEnabled  bool
	HotKeyThreshold     int
	PartitionCount      int
	CleanupInterval     time.Duration
	MaxMemoryMB         int
	PrefetchWorkers     int
	CompressionLevel    int
}

type LocalCache struct {
	data        map[string]*CacheEntry
	accessCount map[string]int64
	lastAccess  map[string]time.Time
	maxSize     int
	mutex       sync.RWMutex
}

type CacheEntry struct {
	Value      interface{}
	ExpiresAt  time.Time
	AccessCount int64
	Size       int64
	Compressed bool
	CreatedAt  time.Time
}

type PreloadingEngine struct {
	patterns        map[string]*AccessPattern
	predictiveQueue chan PreloadRequest
	workers         []*PreloadWorker
	mutex          sync.RWMutex
}

type AccessPattern struct {
	Key              string
	AccessTimes      []time.Time
	Frequency        float64
	PredictedNextAccess time.Time
	Confidence       float64
}

type PreloadRequest struct {
	Key        string
	Generator  func(string) (interface{}, error)
	Priority   int
	RequestedAt time.Time
}

type PreloadWorker struct {
	id       int
	cache    *PerformanceCache
	stopCh   chan bool
	requests chan PreloadRequest
}

type PartitionManager struct {
	partitions []*CachePartition
	hasher     func(string) uint32
}

type CachePartition struct {
	id    int
	mutex sync.RWMutex
	data  map[string]*CacheEntry
}

type CompressionEngine struct {
	enabled bool
	level   int
	mutex   sync.RWMutex
}

type HotKeyDetector struct {
	keyMetrics  map[string]*KeyMetrics
	threshold   int
	mutex       sync.RWMutex
}

type KeyMetrics struct {
	AccessCount    int64
	LastAccess     time.Time
	AverageLatency time.Duration
	IsHot          bool
}

// NewPerformanceCache creates a new high-performance cache
func NewPerformanceCache(config CacheConfig, metricsCollector *monitoring.MetricsCollector) *PerformanceCache {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddress,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	cache := &PerformanceCache{
		redis:            redisClient,
		localCache:       NewLocalCache(config.LocalCacheSize),
		config:           config,
		logger:           logger.NewStructuredLogger("info", "json"),
		metricsCollector: metricsCollector,
		stopCh:           make(chan bool),
	}

	// Initialize engines
	cache.preloadingEngine = NewPreloadingEngine(config.PrefetchWorkers, cache)
	cache.partitionManager = NewPartitionManager(config.PartitionCount)
	cache.compressionEngine = NewCompressionEngine(config.CompressionEnabled, config.CompressionLevel)
	cache.hotKeyDetector = NewHotKeyDetector(config.HotKeyThreshold)

	return cache
}

// Start initializes the performance cache system
func (pc *PerformanceCache) Start(ctx context.Context) error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.started {
		return fmt.Errorf("performance cache already started")
	}

	// Test Redis connection
	if err := pc.redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Start preloading engine
	if pc.config.PreloadingEnabled {
		pc.preloadingEngine.Start(ctx)
	}

	// Start cleanup routine
	go pc.cleanupRoutine(ctx)

	// Start metrics collection
	go pc.metricsRoutine(ctx)

	pc.started = true
	
	pc.logger.Info("performance_cache_started", map[string]interface{}{
		"local_cache_size":    pc.config.LocalCacheSize,
		"partition_count":     pc.config.PartitionCount,
		"preloading_enabled":  pc.config.PreloadingEnabled,
		"compression_enabled": pc.config.CompressionEnabled,
	})

	return nil
}

// Get retrieves a value from cache with intelligent fallback
func (pc *PerformanceCache) Get(ctx context.Context, key string) (interface{}, bool, error) {
	startTime := time.Now()
	defer func() {
		pc.metricsCollector.RecordTiming("cache_get_duration", time.Since(startTime), map[string]string{"operation": "get"})
	}()

	// Update hot key detector
	pc.hotKeyDetector.RecordAccess(key)

	// Try local cache first
	if value, found := pc.localCache.Get(key); found {
		pc.metricsCollector.RecordCounter("cache_hits_total", 1, map[string]string{"level": "local"})
		
		// Update access pattern for preloading
		if pc.config.PreloadingEnabled {
			pc.preloadingEngine.UpdateAccessPattern(key)
		}
		
		return value, true, nil
	}

	// Try Redis cache
	data, err := pc.redis.Get(ctx, key).Result()
	if err == nil {
		var entry CacheEntry
		if err := json.Unmarshal([]byte(data), &entry); err == nil {
			pc.metricsCollector.RecordCounter("cache_hits_total", 1, map[string]string{"level": "redis"})
			
			// Decompress if needed
			if entry.Compressed {
				decompressed, err := pc.compressionEngine.Decompress(entry.Value.([]byte))
				if err == nil {
					entry.Value = decompressed
				}
			}
			
			// Store in local cache
			pc.localCache.Set(key, entry.Value, pc.config.DefaultTTL)
			
			return entry.Value, true, nil
		}
	}

	pc.metricsCollector.RecordCounter("cache_misses_total", 1, nil)
	return nil, false, nil
}

// Set stores a value in cache with intelligent optimization
func (pc *PerformanceCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	startTime := time.Now()
	defer func() {
		pc.metricsCollector.RecordTiming("cache_set_duration", time.Since(startTime), map[string]string{"operation": "set"})
	}()

	entry := &CacheEntry{
		Value:      value,
		ExpiresAt:  time.Now().Add(ttl),
		CreatedAt:  time.Now(),
		AccessCount: 0,
	}

	// Compress if enabled and beneficial
	if pc.config.CompressionEnabled {
		if compressed, shouldCompress := pc.compressionEngine.ShouldCompress(value); shouldCompress {
			compressedData, err := pc.compressionEngine.Compress(compressed)
			if err == nil {
				entry.Value = compressedData
				entry.Compressed = true
				entry.Size = int64(len(compressedData))
			}
		}
	}

	// Store in local cache
	pc.localCache.Set(key, value, ttl)

	// Store in Redis
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cache entry: %w", err)
	}

	err = pc.redis.Set(ctx, key, data, ttl).Err()
	if err != nil {
		pc.metricsCollector.RecordCounter("cache_errors_total", 1, map[string]string{"operation": "set"})
		return fmt.Errorf("failed to set Redis cache: %w", err)
	}

	pc.metricsCollector.RecordCounter("cache_sets_total", 1, nil)
	return nil
}

// Preload preloads data based on access patterns
func (pc *PerformanceCache) Preload(ctx context.Context, key string, generator func(string) (interface{}, error)) {
	if !pc.config.PreloadingEnabled {
		return
	}

	request := PreloadRequest{
		Key:         key,
		Generator:   generator,
		Priority:    pc.calculatePreloadPriority(key),
		RequestedAt: time.Now(),
	}

	pc.preloadingEngine.QueuePreload(request)
}

// GetStats returns comprehensive cache statistics
func (pc *PerformanceCache) GetStats() map[string]interface{} {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	localStats := pc.localCache.GetStats()
	hotKeys := pc.hotKeyDetector.GetHotKeys()
	patterns := pc.preloadingEngine.GetAccessPatterns()

	return map[string]interface{}{
		"local_cache":     localStats,
		"hot_keys":        hotKeys,
		"access_patterns": patterns,
		"started":         pc.started,
		"config":          pc.config,
		"timestamp":       time.Now(),
	}
}

// Helper functions and implementations

func NewLocalCache(maxSize int) *LocalCache {
	return &LocalCache{
		data:        make(map[string]*CacheEntry),
		accessCount: make(map[string]int64),
		lastAccess:  make(map[string]time.Time),
		maxSize:     maxSize,
	}
}

func (lc *LocalCache) Get(key string) (interface{}, bool) {
	lc.mutex.RLock()
	defer lc.mutex.RUnlock()

	entry, exists := lc.data[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	lc.accessCount[key]++
	lc.lastAccess[key] = time.Now()
	entry.AccessCount++

	return entry.Value, true
}

func (lc *LocalCache) Set(key string, value interface{}, ttl time.Duration) {
	lc.mutex.Lock()
	defer lc.mutex.Unlock()

	// Evict if at capacity
	if len(lc.data) >= lc.maxSize {
		lc.evictLRU()
	}

	lc.data[key] = &CacheEntry{
		Value:      value,
		ExpiresAt:  time.Now().Add(ttl),
		CreatedAt:  time.Now(),
		AccessCount: 0,
	}
	lc.lastAccess[key] = time.Now()
}

func (lc *LocalCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, lastAccess := range lc.lastAccess {
		if lastAccess.Before(oldestTime) {
			oldestTime = lastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(lc.data, oldestKey)
		delete(lc.accessCount, oldestKey)
		delete(lc.lastAccess, oldestKey)
	}
}

func (lc *LocalCache) GetStats() map[string]interface{} {
	lc.mutex.RLock()
	defer lc.mutex.RUnlock()

	return map[string]interface{}{
		"size":        len(lc.data),
		"max_size":    lc.maxSize,
		"utilization": float64(len(lc.data)) / float64(lc.maxSize),
	}
}

func NewPreloadingEngine(workers int, cache *PerformanceCache) *PreloadingEngine {
	engine := &PreloadingEngine{
		patterns:        make(map[string]*AccessPattern),
		predictiveQueue: make(chan PreloadRequest, 1000),
		workers:         make([]*PreloadWorker, workers),
	}

	for i := 0; i < workers; i++ {
		engine.workers[i] = &PreloadWorker{
			id:       i,
			cache:    cache,
			stopCh:   make(chan bool),
			requests: engine.predictiveQueue,
		}
	}

	return engine
}

func (pe *PreloadingEngine) Start(ctx context.Context) {
	for _, worker := range pe.workers {
		go worker.Start(ctx)
	}
}

func (pe *PreloadingEngine) UpdateAccessPattern(key string) {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	pattern, exists := pe.patterns[key]
	if !exists {
		pattern = &AccessPattern{
			Key:         key,
			AccessTimes: make([]time.Time, 0, 100),
		}
		pe.patterns[key] = pattern
	}

	pattern.AccessTimes = append(pattern.AccessTimes, time.Now())
	
	// Keep only last 100 accesses
	if len(pattern.AccessTimes) > 100 {
		pattern.AccessTimes = pattern.AccessTimes[1:]
	}

	pe.calculatePrediction(pattern)
}

func (pe *PreloadingEngine) calculatePrediction(pattern *AccessPattern) {
	if len(pattern.AccessTimes) < 3 {
		return
	}

	// Simple frequency-based prediction
	intervals := make([]time.Duration, len(pattern.AccessTimes)-1)
	for i := 1; i < len(pattern.AccessTimes); i++ {
		intervals[i-1] = pattern.AccessTimes[i].Sub(pattern.AccessTimes[i-1])
	}

	// Calculate average interval
	var totalInterval time.Duration
	for _, interval := range intervals {
		totalInterval += interval
	}
	avgInterval := totalInterval / time.Duration(len(intervals))

	pattern.PredictedNextAccess = pattern.AccessTimes[len(pattern.AccessTimes)-1].Add(avgInterval)
	pattern.Frequency = float64(len(pattern.AccessTimes)) / time.Since(pattern.AccessTimes[0]).Hours()
	pattern.Confidence = math.Min(float64(len(pattern.AccessTimes))/10.0, 1.0)
}

func (pe *PreloadingEngine) QueuePreload(request PreloadRequest) {
	select {
	case pe.predictiveQueue <- request:
	default:
		// Queue full, drop request
	}
}

func (pe *PreloadingEngine) GetAccessPatterns() map[string]*AccessPattern {
	pe.mutex.RLock()
	defer pe.mutex.RUnlock()

	result := make(map[string]*AccessPattern)
	for k, v := range pe.patterns {
		result[k] = v
	}
	return result
}

func (pw *PreloadWorker) Start(ctx context.Context) {
	for {
		select {
		case request := <-pw.requests:
			pw.processPreloadRequest(ctx, request)
		case <-pw.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (pw *PreloadWorker) processPreloadRequest(ctx context.Context, request PreloadRequest) {
	// Check if key is already cached
	if _, found, _ := pw.cache.Get(ctx, request.Key); found {
		return
	}

	// Generate value
	value, err := request.Generator(request.Key)
	if err != nil {
		return
	}

	// Store in cache
	pw.cache.Set(ctx, request.Key, value, pw.cache.config.DefaultTTL)
}

func NewPartitionManager(partitionCount int) *PartitionManager {
	partitions := make([]*CachePartition, partitionCount)
	for i := 0; i < partitionCount; i++ {
		partitions[i] = &CachePartition{
			id:   i,
			data: make(map[string]*CacheEntry),
		}
	}

	return &PartitionManager{
		partitions: partitions,
		hasher:     fnvHash,
	}
}

func fnvHash(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}

func NewCompressionEngine(enabled bool, level int) *CompressionEngine {
	return &CompressionEngine{
		enabled: enabled,
		level:   level,
	}
}

func (ce *CompressionEngine) ShouldCompress(value interface{}) ([]byte, bool) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}

	// Only compress if data is larger than 1KB
	return data, len(data) > 1024
}

func (ce *CompressionEngine) Compress(data []byte) ([]byte, error) {
	// Simplified compression - in production, use gzip or similar
	return data, nil
}

func (ce *CompressionEngine) Decompress(data []byte) (interface{}, error) {
	// Simplified decompression
	var result interface{}
	err := json.Unmarshal(data, &result)
	return result, err
}

func NewHotKeyDetector(threshold int) *HotKeyDetector {
	return &HotKeyDetector{
		keyMetrics: make(map[string]*KeyMetrics),
		threshold:  threshold,
	}
}

func (hkd *HotKeyDetector) RecordAccess(key string) {
	hkd.mutex.Lock()
	defer hkd.mutex.Unlock()

	metrics, exists := hkd.keyMetrics[key]
	if !exists {
		metrics = &KeyMetrics{}
		hkd.keyMetrics[key] = metrics
	}

	metrics.AccessCount++
	metrics.LastAccess = time.Now()
	metrics.IsHot = metrics.AccessCount >= int64(hkd.threshold)
}

func (hkd *HotKeyDetector) GetHotKeys() []string {
	hkd.mutex.RLock()
	defer hkd.mutex.RUnlock()

	var hotKeys []string
	for key, metrics := range hkd.keyMetrics {
		if metrics.IsHot {
			hotKeys = append(hotKeys, key)
		}
	}
	return hotKeys
}

func (pc *PerformanceCache) calculatePreloadPriority(key string) int {
	// Simple priority calculation based on access frequency
	return 1
}

func (pc *PerformanceCache) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(pc.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pc.performCleanup()
		case <-pc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (pc *PerformanceCache) performCleanup() {
	// Clean up expired entries in local cache
	pc.localCache.mutex.Lock()
	for key, entry := range pc.localCache.data {
		if time.Now().After(entry.ExpiresAt) {
			delete(pc.localCache.data, key)
			delete(pc.localCache.accessCount, key)
			delete(pc.localCache.lastAccess, key)
		}
	}
	pc.localCache.mutex.Unlock()

	pc.metricsCollector.RecordCounter("cache_cleanup_runs_total", 1, nil)
}

func (pc *PerformanceCache) metricsRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pc.recordMetrics()
		case <-pc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (pc *PerformanceCache) recordMetrics() {
	stats := pc.GetStats()
	
	if localStats, ok := stats["local_cache"].(map[string]interface{}); ok {
		if size, ok := localStats["size"].(int); ok {
			pc.metricsCollector.RecordGauge("cache_local_size", float64(size), nil)
		}
		if util, ok := localStats["utilization"].(float64); ok {
			pc.metricsCollector.RecordGauge("cache_local_utilization", util, nil)
		}
	}

	if hotKeys, ok := stats["hot_keys"].([]string); ok {
		pc.metricsCollector.RecordGauge("cache_hot_keys_count", float64(len(hotKeys)), nil)
	}
}

// Stop gracefully shuts down the performance cache
func (pc *PerformanceCache) Stop() error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if !pc.started {
		return nil
	}

	close(pc.stopCh)
	pc.started = false

	return pc.redis.Close()
}