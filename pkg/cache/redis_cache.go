package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements a distributed cache using Redis
type RedisCache struct {
	client     *redis.Client
	keyPrefix  string
	defaultTTL time.Duration
}

// CacheConfig holds Redis cache configuration
type CacheConfig struct {
	Address     string
	Password    string
	DB          int
	KeyPrefix   string
	DefaultTTL  time.Duration
	MaxRetries  int
	PoolSize    int
	PoolTimeout time.Duration
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(config CacheConfig) (*RedisCache, error) {
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 15 * time.Minute
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.PoolSize == 0 {
		config.PoolSize = 10
	}
	if config.PoolTimeout == 0 {
		config.PoolTimeout = 30 * time.Second
	}

	client := redis.NewClient(&redis.Options{
		Addr:        config.Address,
		Password:    config.Password,
		DB:          config.DB,
		MaxRetries:  config.MaxRetries,
		PoolSize:    config.PoolSize,
		PoolTimeout: config.PoolTimeout,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{
		client:     client,
		keyPrefix:  config.KeyPrefix,
		defaultTTL: config.DefaultTTL,
	}, nil
}

// Set stores a value in the cache
func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	fullKey := c.buildKey(key)
	return c.client.Set(ctx, fullKey, data, ttl).Err()
}

// Get retrieves a value from the cache
func (c *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	fullKey := c.buildKey(key)
	data, err := c.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

// Delete removes a value from the cache
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	fullKey := c.buildKey(key)
	return c.client.Del(ctx, fullKey).Err()
}

// Exists checks if a key exists in the cache
func (c *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := c.buildKey(key)
	result, err := c.client.Exists(ctx, fullKey).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// SetNX sets a value only if the key doesn't exist
func (c *RedisCache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	fullKey := c.buildKey(key)
	result, err := c.client.SetNX(ctx, fullKey, data, ttl).Result()
	return result, err
}

// Expire sets a TTL for an existing key
func (c *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	fullKey := c.buildKey(key)
	return c.client.Expire(ctx, fullKey, ttl).Err()
}

// TTL returns the remaining time to live for a key
func (c *RedisCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	fullKey := c.buildKey(key)
	return c.client.TTL(ctx, fullKey).Result()
}

// GetSet atomically sets a value and returns the old value
func (c *RedisCache) GetSet(ctx context.Context, key string, value interface{}) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("failed to marshal value: %w", err)
	}

	fullKey := c.buildKey(key)
	return c.client.GetSet(ctx, fullKey, data).Result()
}

// Increment atomically increments a numeric value
func (c *RedisCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	fullKey := c.buildKey(key)
	return c.client.IncrBy(ctx, fullKey, delta).Result()
}

// ListPush pushes values to the beginning of a list
func (c *RedisCache) ListPush(ctx context.Context, key string, values ...interface{}) error {
	fullKey := c.buildKey(key)
	return c.client.LPush(ctx, fullKey, values...).Err()
}

// ListPop pops a value from the beginning of a list
func (c *RedisCache) ListPop(ctx context.Context, key string, dest interface{}) error {
	fullKey := c.buildKey(key)
	data, err := c.client.LPop(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return err
	}

	return json.Unmarshal([]byte(data), dest)
}

// ListLength returns the length of a list
func (c *RedisCache) ListLength(ctx context.Context, key string) (int64, error) {
	fullKey := c.buildKey(key)
	return c.client.LLen(ctx, fullKey).Result()
}

// SetAdd adds members to a set
func (c *RedisCache) SetAdd(ctx context.Context, key string, members ...interface{}) error {
	fullKey := c.buildKey(key)
	return c.client.SAdd(ctx, fullKey, members...).Err()
}

// SetMembers returns all members of a set
func (c *RedisCache) SetMembers(ctx context.Context, key string) ([]string, error) {
	fullKey := c.buildKey(key)
	return c.client.SMembers(ctx, fullKey).Result()
}

// SetIsMember checks if a value is a member of a set
func (c *RedisCache) SetIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	fullKey := c.buildKey(key)
	return c.client.SIsMember(ctx, fullKey, member).Result()
}

// HashSet sets fields in a hash
func (c *RedisCache) HashSet(ctx context.Context, key string, fields map[string]interface{}) error {
	fullKey := c.buildKey(key)
	return c.client.HSet(ctx, fullKey, fields).Err()
}

// HashGet gets a field from a hash
func (c *RedisCache) HashGet(ctx context.Context, key, field string) (string, error) {
	fullKey := c.buildKey(key)
	return c.client.HGet(ctx, fullKey, field).Result()
}

// HashGetAll gets all fields from a hash
func (c *RedisCache) HashGetAll(ctx context.Context, key string) (map[string]string, error) {
	fullKey := c.buildKey(key)
	return c.client.HGetAll(ctx, fullKey).Result()
}

// Pipeline creates a new pipeline for batch operations
func (c *RedisCache) Pipeline() redis.Pipeliner {
	return c.client.Pipeline()
}

// Transaction creates a new transaction
func (c *RedisCache) Transaction(ctx context.Context, keys []string, fn func(*redis.Tx) error) error {
	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = c.buildKey(key)
	}

	return c.client.Watch(ctx, fn, fullKeys...)
}

// GetMultiple gets multiple values at once
func (c *RedisCache) GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return make(map[string]interface{}), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = c.buildKey(key)
	}

	values, err := c.client.MGet(ctx, fullKeys...).Result()
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	for i, value := range values {
		if value != nil {
			var parsed interface{}
			if err := json.Unmarshal([]byte(value.(string)), &parsed); err == nil {
				result[keys[i]] = parsed
			}
		}
	}

	return result, nil
}

// SetMultiple sets multiple values at once
func (c *RedisCache) SetMultiple(ctx context.Context, values map[string]interface{}, ttl time.Duration) error {
	if len(values) == 0 {
		return nil
	}

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	pipe := c.client.Pipeline()
	for key, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}
		fullKey := c.buildKey(key)
		pipe.Set(ctx, fullKey, data, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// Clear removes all keys with the configured prefix
func (c *RedisCache) Clear(ctx context.Context) error {
	pattern := c.buildKey("*")
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}

	return nil
}

// Stats returns cache statistics
func (c *RedisCache) Stats(ctx context.Context) (*CacheStats, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	// Parse Redis INFO output for basic stats
	// This is a simplified implementation
	return &CacheStats{
		Hits:   0, // Would need to parse from INFO output
		Misses: 0, // Would need to parse from INFO output
		Keys:   0, // Would need to count keys with prefix
	}, nil
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Health checks the health of the Redis connection
func (c *RedisCache) Health(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// buildKey creates a full key with prefix
func (c *RedisCache) buildKey(key string) string {
	if c.keyPrefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", c.keyPrefix, key)
}

// CacheStats holds cache statistics
type CacheStats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Keys   int64 `json:"keys"`
}

// ErrCacheMiss indicates a cache miss
var ErrCacheMiss = fmt.Errorf("cache miss")

// Cache interface defines the cache operations
type Cache interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string, dest interface{}) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Clear(ctx context.Context) error
	Health(ctx context.Context) error
	Close() error
}

// Ensure RedisCache implements Cache interface
var _ Cache = (*RedisCache)(nil)