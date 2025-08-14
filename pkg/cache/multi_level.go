package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MultiLevelCache implements a multi-tier caching strategy
type MultiLevelCache struct {
	levels []CacheLevel
	stats  CacheStats
	mu     sync.RWMutex
}

// CacheLevel represents a single cache level
type CacheLevel struct {
	Name     string
	Cache    Cache
	TTL      time.Duration
	Priority int
}

// Cache interface for different cache implementations
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Stats() map[string]interface{}
	Close() error
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits         int64
	Misses       int64
	Sets         int64
	Deletes      int64
	Errors       int64
	LastAccess   time.Time
	TotalLatency time.Duration
}

// NewMultiLevelCache creates a new multi-level cache
func NewMultiLevelCache(levels []CacheLevel) (*MultiLevelCache, error) {
	if len(levels) == 0 {
		return nil, fmt.Errorf("at least one cache level is required")
	}
	
	// Sort levels by priority (lower number = higher priority)
	for i := 0; i < len(levels); i++ {
		for j := i + 1; j < len(levels); j++ {
			if levels[i].Priority > levels[j].Priority {
				levels[i], levels[j] = levels[j], levels[i]
			}
		}
	}
	
	return &MultiLevelCache{
		levels: levels,
		stats:  CacheStats{LastAccess: time.Now()},
	}, nil
}

// Get retrieves a value from the cache, checking levels in priority order
func (mlc *MultiLevelCache) Get(ctx context.Context, key string) ([]byte, error) {
	start := time.Now()
	defer func() {
		mlc.mu.Lock()
		mlc.stats.TotalLatency += time.Since(start)
		mlc.stats.LastAccess = time.Now()
		mlc.mu.Unlock()
	}()
	
	var lastErr error
	
	// Check each level in priority order
	for i, level := range mlc.levels {
		value, err := level.Cache.Get(ctx, key)
		if err == nil && value != nil {
			// Cache hit - propagate to higher priority levels
			mlc.mu.Lock()
			mlc.stats.Hits++
			mlc.mu.Unlock()
			
			// Asynchronously populate higher priority levels
			go mlc.populateHigherLevels(ctx, key, value, i)
			
			return value, nil
		}
		
		if err != nil {
			lastErr = err
			mlc.mu.Lock()
			mlc.stats.Errors++
			mlc.mu.Unlock()
		}
	}
	
	// Cache miss
	mlc.mu.Lock()
	mlc.stats.Misses++
	mlc.mu.Unlock()
	
	if lastErr != nil {
		return nil, fmt.Errorf("cache miss with errors: %w", lastErr)
	}
	
	return nil, fmt.Errorf("cache miss")
}

// Set stores a value in all cache levels
func (mlc *MultiLevelCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		mlc.mu.Lock()
		mlc.stats.TotalLatency += time.Since(start)
		mlc.stats.LastAccess = time.Now()
		mlc.stats.Sets++
		mlc.mu.Unlock()
	}()
	
	var errors []error
	
	// Set in all levels concurrently
	var wg sync.WaitGroup
	errorCh := make(chan error, len(mlc.levels))
	
	for _, level := range mlc.levels {
		wg.Add(1)
		go func(l CacheLevel) {
			defer wg.Done()
			
			// Use level-specific TTL if available, otherwise use provided TTL
			levelTTL := ttl
			if l.TTL > 0 {
				levelTTL = l.TTL
			}
			
			if err := l.Cache.Set(ctx, key, value, levelTTL); err != nil {
				errorCh <- fmt.Errorf("level %s: %w", l.Name, err)
			}
		}(level)
	}
	
	wg.Wait()
	close(errorCh)
	
	// Collect errors
	for err := range errorCh {
		errors = append(errors, err)
		mlc.mu.Lock()
		mlc.stats.Errors++
		mlc.mu.Unlock()
	}
	
	// Return error if all levels failed
	if len(errors) == len(mlc.levels) {
		return fmt.Errorf("failed to set in all cache levels: %v", errors)
	}
	
	// Return warning if some levels failed
	if len(errors) > 0 {
		return fmt.Errorf("partial failure setting cache levels: %v", errors)
	}
	
	return nil
}

// Delete removes a key from all cache levels
func (mlc *MultiLevelCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		mlc.mu.Lock()
		mlc.stats.TotalLatency += time.Since(start)
		mlc.stats.LastAccess = time.Now()
		mlc.stats.Deletes++
		mlc.mu.Unlock()
	}()
	
	var errors []error
	
	// Delete from all levels concurrently
	var wg sync.WaitGroup
	errorCh := make(chan error, len(mlc.levels))
	
	for _, level := range mlc.levels {
		wg.Add(1)
		go func(l CacheLevel) {
			defer wg.Done()
			
			if err := l.Cache.Delete(ctx, key); err != nil {
				errorCh <- fmt.Errorf("level %s: %w", l.Name, err)
			}
		}(level)
	}
	
	wg.Wait()
	close(errorCh)
	
	// Collect errors
	for err := range errorCh {
		errors = append(errors, err)
		mlc.mu.Lock()
		mlc.stats.Errors++
		mlc.mu.Unlock()
	}
	
	// Return combined errors if any occurred
	if len(errors) > 0 {
		return fmt.Errorf("errors deleting from cache levels: %v", errors)
	}
	
	return nil
}

// Exists checks if a key exists in any cache level
func (mlc *MultiLevelCache) Exists(ctx context.Context, key string) (bool, error) {
	for _, level := range mlc.levels {
		exists, err := level.Cache.Exists(ctx, key)
		if err != nil {
			continue // Try next level
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Stats returns aggregated cache statistics
func (mlc *MultiLevelCache) Stats() CacheStats {
	mlc.mu.RLock()
	defer mlc.mu.RUnlock()
	return mlc.stats
}

// DetailedStats returns statistics for each cache level
func (mlc *MultiLevelCache) DetailedStats() map[string]interface{} {
	mlc.mu.RLock()
	defer mlc.mu.RUnlock()
	
	result := make(map[string]interface{})
	result["overall"] = mlc.stats
	
	levels := make(map[string]interface{})
	for _, level := range mlc.levels {
		levels[level.Name] = level.Cache.Stats()
	}
	result["levels"] = levels
	
	// Calculate hit ratio
	total := mlc.stats.Hits + mlc.stats.Misses
	hitRatio := 0.0
	if total > 0 {
		hitRatio = float64(mlc.stats.Hits) / float64(total) * 100
	}
	result["hit_ratio_percent"] = hitRatio
	
	// Calculate average latency
	avgLatency := 0.0
	if total > 0 {
		avgLatency = float64(mlc.stats.TotalLatency.Nanoseconds()) / float64(total) / 1e6 // Convert to milliseconds
	}
	result["avg_latency_ms"] = avgLatency
	
	return result
}

// Close closes all cache levels
func (mlc *MultiLevelCache) Close() error {
	var errors []error
	
	for _, level := range mlc.levels {
		if err := level.Cache.Close(); err != nil {
			errors = append(errors, fmt.Errorf("level %s: %w", level.Name, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("errors closing cache levels: %v", errors)
	}
	
	return nil
}

// populateHigherLevels asynchronously populates higher priority cache levels
func (mlc *MultiLevelCache) populateHigherLevels(ctx context.Context, key string, value []byte, hitLevelIndex int) {
	// Only populate levels with higher priority (lower index)
	for i := 0; i < hitLevelIndex; i++ {
		level := mlc.levels[i]
		
		levelTTL := level.TTL
		if levelTTL <= 0 {
			levelTTL = 5 * time.Minute // Default TTL
		}
		
		// Use a timeout context for background population
		populateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		go func(l CacheLevel, ctx context.Context) {
			defer cancel()
			if err := l.Cache.Set(ctx, key, value, levelTTL); err != nil {
				// Log error but don't fail the operation
				mlc.mu.Lock()
				mlc.stats.Errors++
				mlc.mu.Unlock()
			}
		}(level, populateCtx)
	}
}

// Warmup pre-populates the cache with frequently accessed data
func (mlc *MultiLevelCache) Warmup(ctx context.Context, data map[string][]byte, ttl time.Duration) error {
	var errors []error
	
	for key, value := range data {
		if err := mlc.Set(ctx, key, value, ttl); err != nil {
			errors = append(errors, fmt.Errorf("key %s: %w", key, err))
		}
		
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("warmup cancelled: %w", ctx.Err())
		default:
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("warmup completed with errors: %v", errors)
	}
	
	return nil
}

// GetWithFallback retrieves a value from cache or executes a fallback function
func (mlc *MultiLevelCache) GetWithFallback(ctx context.Context, key string, ttl time.Duration, fallback func(ctx context.Context, key string) ([]byte, error)) ([]byte, error) {
	// Try to get from cache first
	value, err := mlc.Get(ctx, key)
	if err == nil {
		return value, nil
	}
	
	// Cache miss, execute fallback
	value, err = fallback(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("fallback failed: %w", err)
	}
	
	// Asynchronously store in cache
	go func() {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if err := mlc.Set(cacheCtx, key, value, ttl); err != nil {
			mlc.mu.Lock()
			mlc.stats.Errors++
			mlc.mu.Unlock()
		}
	}()
	
	return value, nil
}

// Refresh updates a cache entry with a new value and TTL
func (mlc *MultiLevelCache) Refresh(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// Delete old entry first
	if err := mlc.Delete(ctx, key); err != nil {
		// Log but continue - deletion failure shouldn't prevent refresh
		mlc.mu.Lock()
		mlc.stats.Errors++
		mlc.mu.Unlock()
	}
	
	// Set new entry
	return mlc.Set(ctx, key, value, ttl)
}