package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type RedisCache struct {
	client *redis.Client
}

type CacheOptions struct {
	TTL        time.Duration
	Namespace  string
	Compress   bool
}

func NewRedisCache(addr, password string, db int) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisCache{client: rdb}
}

func (r *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("redis get error: %w", err)
	}

	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return fmt.Errorf("failed to unmarshal cached value: %w", err)
	}

	return nil
}

func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, opts *CacheOptions) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	ttl := 24 * time.Hour
	if opts != nil && opts.TTL > 0 {
		ttl = opts.TTL
	}

	if opts != nil && opts.Namespace != "" {
		key = fmt.Sprintf("%s:%s", opts.Namespace, key)
	}

	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}

	return nil
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	return result > 0, err
}

func (r *RedisCache) Increment(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

func (r *RedisCache) SetWithExpiration(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.Set(ctx, key, data, expiration).Err()
}

func (r *RedisCache) GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return make(map[string]interface{}), nil
	}

	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis mget error: %w", err)
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

func (r *RedisCache) SetMultiple(ctx context.Context, items map[string]interface{}, opts *CacheOptions) error {
	pipe := r.client.Pipeline()

	ttl := 24 * time.Hour
	if opts != nil && opts.TTL > 0 {
		ttl = opts.TTL
	}

	for key, value := range items {
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}

		if opts != nil && opts.Namespace != "" {
			key = fmt.Sprintf("%s:%s", opts.Namespace, key)
		}

		pipe.Set(ctx, key, data, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisCache) FlushNamespace(ctx context.Context, namespace string) error {
	keys, err := r.client.Keys(ctx, fmt.Sprintf("%s:*", namespace)).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys for namespace: %w", err)
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}

	return nil
}

func (r *RedisCache) Close() error {
	return r.client.Close()
}

func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *RedisCache) Stats(ctx context.Context) (map[string]string, error) {
	info, err := r.client.Info(ctx, "memory", "stats").Result()
	if err != nil {
		return nil, err
	}

	stats := make(map[string]string)
	stats["info"] = info

	return stats, nil
}

type ArtifactCache struct {
	cache *RedisCache
}

func NewArtifactCache(redisCache *RedisCache) *ArtifactCache {
	return &ArtifactCache{cache: redisCache}
}

func (a *ArtifactCache) GetArtifact(ctx context.Context, id string) (*types.Artifact, error) {
	key := fmt.Sprintf("artifact:%s", id)
	var artifact types.Artifact
	
	err := a.cache.Get(ctx, key, &artifact)
	if err != nil {
		return nil, err
	}

	return &artifact, nil
}

func (a *ArtifactCache) SetArtifact(ctx context.Context, artifact *types.Artifact) error {
	key := fmt.Sprintf("artifact:%s", artifact.ID.String())
	opts := &CacheOptions{
		TTL:       6 * time.Hour,
		Namespace: "artifacts",
	}

	return a.cache.Set(ctx, key, artifact, opts)
}

func (a *ArtifactCache) GetProvenanceGraph(ctx context.Context, id string) (*types.ProvenanceGraph, error) {
	key := fmt.Sprintf("provenance_graph:%s", id)
	var graph types.ProvenanceGraph
	
	err := a.cache.Get(ctx, key, &graph)
	if err != nil {
		return nil, err
	}

	return &graph, nil
}

func (a *ArtifactCache) SetProvenanceGraph(ctx context.Context, graph *types.ProvenanceGraph) error {
	key := fmt.Sprintf("provenance_graph:%s", graph.ID.String())
	opts := &CacheOptions{
		TTL:       2 * time.Hour,
		Namespace: "provenance",
	}

	return a.cache.Set(ctx, key, graph, opts)
}

func (a *ArtifactCache) GetSBOM(ctx context.Context, id string) (*types.SBOM, error) {
	key := fmt.Sprintf("sbom:%s", id)
	var sbom types.SBOM
	
	err := a.cache.Get(ctx, key, &sbom)
	if err != nil {
		return nil, err
	}

	return &sbom, nil
}

func (a *ArtifactCache) SetSBOM(ctx context.Context, sbom *types.SBOM) error {
	key := fmt.Sprintf("sbom:%s", sbom.ID.String())
	opts := &CacheOptions{
		TTL:       12 * time.Hour,
		Namespace: "sboms",
	}

	return a.cache.Set(ctx, key, sbom, opts)
}

func (a *ArtifactCache) InvalidateArtifact(ctx context.Context, id string) error {
	keys := []string{
		fmt.Sprintf("artifact:%s", id),
		fmt.Sprintf("artifacts:artifact:%s", id),
	}

	for _, key := range keys {
		if err := a.cache.Delete(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

type RateLimiter struct {
	cache *RedisCache
}

func NewRateLimiter(redisCache *RedisCache) *RateLimiter {
	return &RateLimiter{cache: redisCache}
}

func (r *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, error) {
	windowKey := fmt.Sprintf("rate_limit:%s:%d", key, time.Now().Unix()/int64(window.Seconds()))
	
	count, err := r.cache.Increment(ctx, windowKey)
	if err != nil {
		return false, err
	}

	if count == 1 {
		if err := r.cache.SetWithExpiration(ctx, windowKey, count, window); err != nil {
			return false, err
		}
	}

	return count <= limit, nil
}

func (r *RateLimiter) GetUsage(ctx context.Context, key string, window time.Duration) (int64, error) {
	windowKey := fmt.Sprintf("rate_limit:%s:%d", key, time.Now().Unix()/int64(window.Seconds()))
	
	var count int64
	err := r.cache.Get(ctx, windowKey, &count)
	if err != nil {
		if err == ErrCacheMiss {
			return 0, nil
		}
		return 0, err
	}

	return count, nil
}

var ErrCacheMiss = fmt.Errorf("cache miss")