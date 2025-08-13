package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache provides Redis-based caching with advanced features
type RedisCache struct {
	client       *redis.Client
	keyPrefix    string
	defaultTTL   time.Duration
	compression  bool
	metrics      *CacheMetrics
}

// CacheConfig defines configuration for Redis cache
type CacheConfig struct {
	Address         string        `json:"address"`
	Password        string        `json:"password"`
	Database        int           `json:"database"`
	PoolSize        int           `json:"pool_size"`
	MinIdleConns    int           `json:"min_idle_conns"`
	MaxRetries      int           `json:"max_retries"`
	DialTimeout     time.Duration `json:"dial_timeout"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	PoolTimeout     time.Duration `json:"pool_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	IdleCheckFreq   time.Duration `json:"idle_check_frequency"`
	KeyPrefix       string        `json:"key_prefix"`
	DefaultTTL      time.Duration `json:"default_ttl"`
	EnableMetrics   bool          `json:"enable_metrics"`
	Compression     bool          `json:"compression"`
}

// DefaultRedisConfig returns a default Redis configuration
func DefaultRedisConfig() CacheConfig {
	return CacheConfig{
		Address:       "localhost:6379",
		Password:      "",
		Database:      0,
		PoolSize:      100,
		MinIdleConns:  10,
		MaxRetries:    3,
		DialTimeout:   5 * time.Second,
		ReadTimeout:   3 * time.Second,
		WriteTimeout:  3 * time.Second,
		PoolTimeout:   4 * time.Second,
		IdleTimeout:   5 * time.Minute,
		IdleCheckFreq: 1 * time.Minute,
		KeyPrefix:     "provenance:",
		DefaultTTL:    1 * time.Hour,
		EnableMetrics: true,
		Compression:   true,
	}
}

// CacheMetrics tracks cache performance metrics
type CacheMetrics struct {
	Hits            int64         `json:"hits"`
	Misses          int64         `json:"misses"`
	Sets            int64         `json:"sets"`
	Deletes         int64         `json:"deletes"`
	Errors          int64         `json:"errors"`
	TotalLatency    time.Duration `json:"total_latency"`
	OperationCount  int64         `json:"operation_count"`
	LastResetTime   time.Time     `json:"last_reset_time"`
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Data        interface{} `json:"data"`
	CreatedAt   time.Time   `json:"created_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	AccessCount int64       `json:"access_count"`
	Version     string      `json:"version"`
	Tags        []string    `json:"tags,omitempty"`
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(config CacheConfig) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:           config.Address,
		Password:       config.Password,
		DB:             config.Database,
		PoolSize:       config.PoolSize,
		MinIdleConns:   config.MinIdleConns,
		MaxRetries:     config.MaxRetries,
		DialTimeout:    config.DialTimeout,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		PoolTimeout:    config.PoolTimeout,
		IdleTimeout:    config.IdleTimeout,
		IdleCheckFreq:  config.IdleCheckFreq,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	var metrics *CacheMetrics
	if config.EnableMetrics {
		metrics = &CacheMetrics{
			LastResetTime: time.Now(),
		}
	}

	return &RedisCache{
		client:      rdb,
		keyPrefix:   config.KeyPrefix,
		defaultTTL:  config.DefaultTTL,
		compression: config.Compression,
		metrics:     metrics,
	}, nil
}

// Get retrieves a value from cache
func (rc *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	start := time.Now()
	defer rc.recordMetrics("get", start, nil)

	fullKey := rc.keyPrefix + key
	result, err := rc.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			rc.recordMiss()
			return nil, nil
		}
		rc.recordError()
		return nil, fmt.Errorf("cache get error: %w", err)
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(result), &entry); err != nil {
		rc.recordError()
		return nil, fmt.Errorf("cache unmarshal error: %w", err)
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		rc.client.Del(ctx, fullKey)
		rc.recordMiss()
		return nil, nil
	}

	// Update access count
	entry.AccessCount++
	rc.updateAccessCount(ctx, fullKey, entry.AccessCount)

	rc.recordHit()
	return entry.Data, nil
}

// Set stores a value in cache with TTL
func (rc *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer rc.recordMetrics("set", start, nil)

	if ttl <= 0 {
		ttl = rc.defaultTTL
	}

	entry := CacheEntry{
		Data:        value,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		AccessCount: 0,
		Version:     "1.0",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		rc.recordError()
		return fmt.Errorf("cache marshal error: %w", err)
	}

	fullKey := rc.keyPrefix + key
	if err := rc.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		rc.recordError()
		return fmt.Errorf("cache set error: %w", err)
	}

	rc.recordSet()
	return nil
}

// SetWithTags stores a value with tags for efficient invalidation
func (rc *RedisCache) SetWithTags(ctx context.Context, key string, value interface{}, ttl time.Duration, tags []string) error {
	start := time.Now()
	defer rc.recordMetrics("set_with_tags", start, nil)

	if ttl <= 0 {
		ttl = rc.defaultTTL
	}

	entry := CacheEntry{
		Data:        value,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		AccessCount: 0,
		Version:     "1.0",
		Tags:        tags,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		rc.recordError()
		return fmt.Errorf("cache marshal error: %w", err)
	}

	fullKey := rc.keyPrefix + key
	
	// Use pipeline for atomic operations
	pipe := rc.client.Pipeline()
	pipe.Set(ctx, fullKey, data, ttl)
	
	// Store tag mappings for efficient invalidation
	for _, tag := range tags {
		tagKey := rc.keyPrefix + "tag:" + tag
		pipe.SAdd(ctx, tagKey, key)
		pipe.Expire(ctx, tagKey, ttl)
	}
	
	if _, err := pipe.Exec(ctx); err != nil {
		rc.recordError()
		return fmt.Errorf("cache pipeline error: %w", err)
	}

	rc.recordSet()
	return nil
}

// Delete removes a value from cache
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer rc.recordMetrics("delete", start, nil)

	fullKey := rc.keyPrefix + key
	if err := rc.client.Del(ctx, fullKey).Err(); err != nil {
		rc.recordError()
		return fmt.Errorf("cache delete error: %w", err)
	}

	rc.recordDelete()
	return nil
}

// DeleteByTag removes all cache entries with the given tag
func (rc *RedisCache) DeleteByTag(ctx context.Context, tag string) error {
	start := time.Now()
	defer rc.recordMetrics("delete_by_tag", start, nil)

	tagKey := rc.keyPrefix + "tag:" + tag
	keys, err := rc.client.SMembers(ctx, tagKey).Result()
	if err != nil {
		rc.recordError()
		return fmt.Errorf("cache tag lookup error: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	// Prepare full keys for deletion
	fullKeys := make([]string, len(keys)+1)
	for i, key := range keys {
		fullKeys[i] = rc.keyPrefix + key
	}
	fullKeys[len(keys)] = tagKey // Also delete the tag set

	if err := rc.client.Del(ctx, fullKeys...).Err(); err != nil {
		rc.recordError()
		return fmt.Errorf("cache batch delete error: %w", err)
	}

	rc.recordDelete()
	return nil
}

// Exists checks if a key exists in cache
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	defer rc.recordMetrics("exists", start, nil)

	fullKey := rc.keyPrefix + key
	result, err := rc.client.Exists(ctx, fullKey).Result()
	if err != nil {
		rc.recordError()
		return false, fmt.Errorf("cache exists error: %w", err)
	}

	return result > 0, nil
}

// GetOrSet implements cache-aside pattern
func (rc *RedisCache) GetOrSet(ctx context.Context, key string, fn func() (interface{}, error), ttl time.Duration) (interface{}, error) {
	// Try to get from cache first
	if value, err := rc.Get(ctx, key); err == nil && value != nil {
		return value, nil
	}

	// Cache miss - fetch from source
	value, err := fn()
	if err != nil {
		return nil, err
	}

	// Store in cache for next time
	if setErr := rc.Set(ctx, key, value, ttl); setErr != nil {
		// Log error but don't fail the request
		// In production, this should be logged properly
	}

	return value, nil
}

// IncrementCounter atomically increments a counter
func (rc *RedisCache) IncrementCounter(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	start := time.Now()
	defer rc.recordMetrics("increment", start, nil)

	fullKey := rc.keyPrefix + "counter:" + key
	
	pipe := rc.client.Pipeline()
	incr := pipe.IncrBy(ctx, fullKey, delta)
	pipe.Expire(ctx, fullKey, ttl)
	
	if _, err := pipe.Exec(ctx); err != nil {
		rc.recordError()
		return 0, fmt.Errorf("cache increment error: %w", err)
	}

	return incr.Val(), nil
}

// GetCounter gets a counter value
func (rc *RedisCache) GetCounter(ctx context.Context, key string) (int64, error) {
	start := time.Now()
	defer rc.recordMetrics("get_counter", start, nil)

	fullKey := rc.keyPrefix + "counter:" + key
	result, err := rc.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		rc.recordError()
		return 0, fmt.Errorf("cache get counter error: %w", err)
	}

	value, err := strconv.ParseInt(result, 10, 64)
	if err != nil {
		rc.recordError()
		return 0, fmt.Errorf("cache counter parse error: %w", err)
	}

	return value, nil
}

// Lock implements distributed locking
func (rc *RedisCache) Lock(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	start := time.Now()
	defer rc.recordMetrics("lock", start, nil)

	fullKey := rc.keyPrefix + "lock:" + key
	result, err := rc.client.SetNX(ctx, fullKey, "locked", expiration).Result()
	if err != nil {
		rc.recordError()
		return false, fmt.Errorf("cache lock error: %w", err)
	}

	return result, nil
}

// Unlock releases a distributed lock
func (rc *RedisCache) Unlock(ctx context.Context, key string) error {
	start := time.Now()
	defer rc.recordMetrics("unlock", start, nil)

	fullKey := rc.keyPrefix + "lock:" + key
	if err := rc.client.Del(ctx, fullKey).Err(); err != nil {
		rc.recordError()
		return fmt.Errorf("cache unlock error: %w", err)
	}

	return nil
}

// FlushAll clears all cache entries
func (rc *RedisCache) FlushAll(ctx context.Context) error {
	start := time.Now()
	defer rc.recordMetrics("flush", start, nil)

	if err := rc.client.FlushDB(ctx).Err(); err != nil {
		rc.recordError()
		return fmt.Errorf("cache flush error: %w", err)
	}

	return nil
}

// GetMetrics returns cache performance metrics
func (rc *RedisCache) GetMetrics() *CacheMetrics {
	if rc.metrics == nil {
		return nil
	}
	
	// Return a copy to prevent data races
	return &CacheMetrics{
		Hits:           rc.metrics.Hits,
		Misses:         rc.metrics.Misses,
		Sets:           rc.metrics.Sets,
		Deletes:        rc.metrics.Deletes,
		Errors:         rc.metrics.Errors,
		TotalLatency:   rc.metrics.TotalLatency,
		OperationCount: rc.metrics.OperationCount,
		LastResetTime:  rc.metrics.LastResetTime,
	}
}

// ResetMetrics resets performance metrics
func (rc *RedisCache) ResetMetrics() {
	if rc.metrics != nil {
		rc.metrics.Hits = 0
		rc.metrics.Misses = 0
		rc.metrics.Sets = 0
		rc.metrics.Deletes = 0
		rc.metrics.Errors = 0
		rc.metrics.TotalLatency = 0
		rc.metrics.OperationCount = 0
		rc.metrics.LastResetTime = time.Now()
	}
}

// HitRatio calculates the cache hit ratio
func (rc *RedisCache) HitRatio() float64 {
	if rc.metrics == nil {
		return 0
	}
	
	total := rc.metrics.Hits + rc.metrics.Misses
	if total == 0 {
		return 0
	}
	
	return float64(rc.metrics.Hits) / float64(total)
}

// AverageLatency calculates average operation latency
func (rc *RedisCache) AverageLatency() time.Duration {
	if rc.metrics == nil || rc.metrics.OperationCount == 0 {
		return 0
	}
	
	return rc.metrics.TotalLatency / time.Duration(rc.metrics.OperationCount)
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

// Health performs a health check on the Redis connection
func (rc *RedisCache) Health(ctx context.Context) error {
	return rc.client.Ping(ctx).Err()
}

// Helper methods for metrics recording

func (rc *RedisCache) recordHit() {
	if rc.metrics != nil {
		rc.metrics.Hits++
	}
}

func (rc *RedisCache) recordMiss() {
	if rc.metrics != nil {
		rc.metrics.Misses++
	}
}

func (rc *RedisCache) recordSet() {
	if rc.metrics != nil {
		rc.metrics.Sets++
	}
}

func (rc *RedisCache) recordDelete() {
	if rc.metrics != nil {
		rc.metrics.Deletes++
	}
}

func (rc *RedisCache) recordError() {
	if rc.metrics != nil {
		rc.metrics.Errors++
	}
}

func (rc *RedisCache) recordMetrics(operation string, start time.Time, err error) {
	if rc.metrics != nil {
		rc.metrics.OperationCount++
		rc.metrics.TotalLatency += time.Since(start)
		
		if err != nil {
			rc.metrics.Errors++
		}
	}
}

func (rc *RedisCache) updateAccessCount(ctx context.Context, key string, count int64) {
	// Update access count asynchronously to avoid impacting performance
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		// Use a Lua script for atomic update
		script := `
			local key = KEYS[1]
			local count = ARGV[1]
			local entry = redis.call('GET', key)
			if entry then
				local decoded = cjson.decode(entry)
				decoded.access_count = tonumber(count)
				redis.call('SET', key, cjson.encode(decoded))
			end
			return true
		`
		rc.client.Eval(ctx, script, []string{key}, count)
	}()
}