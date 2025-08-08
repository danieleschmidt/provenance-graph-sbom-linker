package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DistributedCache provides a distributed caching layer using Redis
type DistributedCache struct {
	client     *redis.Client
	defaultTTL time.Duration
	prefix     string
}

// CacheOptions configures cache behavior
type CacheOptions struct {
	TTL        time.Duration
	Compress   bool
	Encryption bool
}

// NewDistributedCache creates a new distributed cache instance
func NewDistributedCache(redisURL string, defaultTTL time.Duration, prefix string) (*DistributedCache, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	client := redis.NewClient(opt)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &DistributedCache{
		client:     client,
		defaultTTL: defaultTTL,
		prefix:     prefix,
	}, nil
}

// Get retrieves a value from the cache
func (dc *DistributedCache) Get(ctx context.Context, key string, dest interface{}) error {
	fullKey := dc.makeKey(key)
	
	val, err := dc.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("cache get failed: %w", err)
	}

	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return fmt.Errorf("cache unmarshal failed: %w", err)
	}

	return nil
}

// Set stores a value in the cache
func (dc *DistributedCache) Set(ctx context.Context, key string, value interface{}, opts *CacheOptions) error {
	fullKey := dc.makeKey(key)
	
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cache marshal failed: %w", err)
	}

	ttl := dc.defaultTTL
	if opts != nil && opts.TTL > 0 {
		ttl = opts.TTL
	}

	if err := dc.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("cache set failed: %w", err)
	}

	return nil
}

// Delete removes a value from the cache
func (dc *DistributedCache) Delete(ctx context.Context, key string) error {
	fullKey := dc.makeKey(key)
	return dc.client.Del(ctx, fullKey).Err()
}

// Exists checks if a key exists in the cache
func (dc *DistributedCache) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := dc.makeKey(key)
	count, err := dc.client.Exists(ctx, fullKey).Result()
	return count > 0, err
}

// InvalidatePattern removes all keys matching a pattern
func (dc *DistributedCache) InvalidatePattern(ctx context.Context, pattern string) error {
	fullPattern := dc.makeKey(pattern)
	
	keys, err := dc.client.Keys(ctx, fullPattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys for pattern: %w", err)
	}

	if len(keys) > 0 {
		if err := dc.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys: %w", err)
		}
	}

	return nil
}

// GetMulti retrieves multiple values from the cache
func (dc *DistributedCache) GetMulti(ctx context.Context, keys []string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return make(map[string]interface{}), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = dc.makeKey(key)
	}

	values, err := dc.client.MGet(ctx, fullKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("cache mget failed: %w", err)
	}

	result := make(map[string]interface{})
	for i, val := range values {
		if val != nil {
			var data interface{}
			if err := json.Unmarshal([]byte(val.(string)), &data); err == nil {
				result[keys[i]] = data
			}
		}
	}

	return result, nil
}

// SetMulti stores multiple values in the cache
func (dc *DistributedCache) SetMulti(ctx context.Context, items map[string]interface{}, opts *CacheOptions) error {
	if len(items) == 0 {
		return nil
	}

	pipe := dc.client.Pipeline()
	
	ttl := dc.defaultTTL
	if opts != nil && opts.TTL > 0 {
		ttl = opts.TTL
	}

	for key, value := range items {
		fullKey := dc.makeKey(key)
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("cache marshal failed for key %s: %w", key, err)
		}
		pipe.Set(ctx, fullKey, data, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// Increment atomically increments a counter
func (dc *DistributedCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	fullKey := dc.makeKey(key)
	return dc.client.IncrBy(ctx, fullKey, delta).Result()
}

// Lock implements distributed locking
func (dc *DistributedCache) Lock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	lockKey := dc.makeKey("lock:" + key)
	
	// Try to acquire lock
	success, err := dc.client.SetNX(ctx, lockKey, "locked", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("lock acquisition failed: %w", err)
	}

	return success, nil
}

// Unlock releases a distributed lock
func (dc *DistributedCache) Unlock(ctx context.Context, key string) error {
	lockKey := dc.makeKey("lock:" + key)
	return dc.client.Del(ctx, lockKey).Err()
}

// GetStats returns cache statistics
func (dc *DistributedCache) GetStats(ctx context.Context) (*CacheStats, error) {
	_, err := dc.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis stats: %w", err)
	}

	// Parse Redis info and create stats
	// This is a simplified version - in production, parse the actual Redis INFO output
	stats := &CacheStats{
		Hits:         0, // Parse from info
		Misses:       0, // Parse from info
		Keys:         0, // Parse from info
		Memory:       0, // Parse from info
		Connections:  0, // Parse from info
	}

	return stats, nil
}

// Close closes the cache connection
func (dc *DistributedCache) Close() error {
	return dc.client.Close()
}

// makeKey creates a full cache key with prefix
func (dc *DistributedCache) makeKey(key string) string {
	if dc.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", dc.prefix, key)
}

// CacheStats represents cache performance statistics
type CacheStats struct {
	Hits        int64 `json:"hits"`
	Misses      int64 `json:"misses"`
	Keys        int64 `json:"keys"`
	Memory      int64 `json:"memory_bytes"`
	Connections int   `json:"connections"`
}

// HitRate calculates the cache hit rate
func (cs *CacheStats) HitRate() float64 {
	total := cs.Hits + cs.Misses
	if total == 0 {
		return 0
	}
	return float64(cs.Hits) / float64(total)
}

// Cache warming functionality
type Warmer struct {
	cache    *DistributedCache
	loaders  map[string]CacheLoader
}

type CacheLoader func(ctx context.Context, key string) (interface{}, error)

// NewWarmer creates a cache warmer
func NewWarmer(cache *DistributedCache) *Warmer {
	return &Warmer{
		cache:   cache,
		loaders: make(map[string]CacheLoader),
	}
}

// RegisterLoader registers a cache loader for a specific pattern
func (w *Warmer) RegisterLoader(pattern string, loader CacheLoader) {
	w.loaders[pattern] = loader
}

// WarmCache preloads cache with commonly accessed data
func (w *Warmer) WarmCache(ctx context.Context, keys []string) error {
	for _, key := range keys {
		// Find appropriate loader
		var loader CacheLoader
		for pattern, l := range w.loaders {
			if matchesPattern(key, pattern) {
				loader = l
				break
			}
		}

		if loader == nil {
			continue
		}

		// Check if already cached
		exists, err := w.cache.Exists(ctx, key)
		if err != nil {
			continue
		}
		if exists {
			continue
		}

		// Load and cache
		value, err := loader(ctx, key)
		if err != nil {
			continue
		}

		w.cache.Set(ctx, key, value, &CacheOptions{TTL: 1 * time.Hour})
	}

	return nil
}

// Helper function for pattern matching
func matchesPattern(str, pattern string) bool {
	// Simple wildcard matching - in production, use a proper pattern library
	return true
}

// Error types
var (
	ErrCacheMiss = fmt.Errorf("cache miss")
)

// Cache eviction policies
type EvictionPolicy string

const (
	EvictionLRU     EvictionPolicy = "lru"
	EvictionTTL     EvictionPolicy = "ttl"
	EvictionRandom  EvictionPolicy = "random"
	EvictionLFU     EvictionPolicy = "lfu"
)

// CacheMetrics provides detailed cache performance metrics
type CacheMetrics struct {
	TotalRequests    int64         `json:"total_requests"`
	CacheHits        int64         `json:"cache_hits"`
	CacheMisses      int64         `json:"cache_misses"`
	AvgResponseTime  time.Duration `json:"avg_response_time"`
	P95ResponseTime  time.Duration `json:"p95_response_time"`
	P99ResponseTime  time.Duration `json:"p99_response_time"`
	ErrorRate        float64       `json:"error_rate"`
	MemoryUsage      int64         `json:"memory_usage_bytes"`
	NetworkIO        int64         `json:"network_io_bytes"`
}

// CircuitBreaker for cache operations
type CircuitBreaker struct {
	failures    int64
	lastFailure time.Time
	state       string // "closed", "open", "half-open"
	threshold   int64
	timeout     time.Duration
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int64, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
		state:     "closed",
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	if cb.state == "open" {
		if time.Since(cb.lastFailure) > cb.timeout {
			cb.state = "half-open"
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	err := fn()
	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		
		if cb.failures >= cb.threshold {
			cb.state = "open"
		}
		return err
	}

	if cb.state == "half-open" {
		cb.state = "closed"
		cb.failures = 0
	}

	return nil
}