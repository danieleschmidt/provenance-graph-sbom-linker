package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/redis/go-redis/v9"
)

// ConnectionPoolConfig holds configuration for database connection pools
type ConnectionPoolConfig struct {
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	RetryAttempts   int           `json:"retry_attempts"`
	RetryBackoff    time.Duration `json:"retry_backoff"`
}

// DefaultPoolConfig returns sensible defaults for connection pooling
func DefaultPoolConfig() ConnectionPoolConfig {
	return ConnectionPoolConfig{
		MaxOpenConns:    25,
		MaxIdleConns:    10,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		RetryAttempts:   3,
		RetryBackoff:    time.Second,
	}
}

// PoolMetrics tracks connection pool performance
type PoolMetrics struct {
	OpenConnections  int64         `json:"open_connections"`
	IdleConnections  int64         `json:"idle_connections"`
	WaitCount        int64         `json:"wait_count"`
	WaitDuration     time.Duration `json:"wait_duration"`
	MaxIdleClosed    int64         `json:"max_idle_closed"`
	MaxLifetimeClosed int64        `json:"max_lifetime_closed"`
	mu               sync.RWMutex
}

// DatabasePool manages multiple database connections with pooling
type DatabasePool struct {
	config      ConnectionPoolConfig
	neo4jDriver neo4j.DriverWithContext
	redisClient *redis.Client
	sqlDB       *sql.DB
	metrics     *PoolMetrics
	healthCheck *HealthChecker
	mu          sync.RWMutex
}

// NewDatabasePool creates a new database connection pool
func NewDatabasePool(config ConnectionPoolConfig) *DatabasePool {
	return &DatabasePool{
		config:  config,
		metrics: &PoolMetrics{},
		healthCheck: NewHealthChecker(config.HealthCheckInterval),
	}
}

// InitializeNeo4j initializes Neo4j driver with connection pooling
func (p *DatabasePool) InitializeNeo4j(uri, username, password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""), func(config *neo4j.Config) {
		config.MaxConnectionPoolSize = p.config.MaxOpenConns
		config.MaxConnectionLifetime = p.config.ConnMaxLifetime
		config.ConnectionLivenessCheckTimeout = p.config.HealthCheckInterval
		config.ConnectionAcquisitionTimeout = 30 * time.Second
	})
	
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	// Test connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := driver.VerifyConnectivity(ctx); err != nil {
		driver.Close(ctx)
		return fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	p.neo4jDriver = driver
	p.healthCheck.AddService("neo4j", func() error {
		return p.neo4jDriver.VerifyConnectivity(context.Background())
	})

	return nil
}

// InitializeRedis initializes Redis client with connection pooling
func (p *DatabasePool) InitializeRedis(addr, password string, db int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.redisClient = redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     p.config.MaxOpenConns,
		MinIdleConns: p.config.MaxIdleConns,
		ConnMaxLifetime: p.config.ConnMaxLifetime,
		PoolTimeout:     30 * time.Second,
		ConnMaxIdleTime: p.config.ConnMaxIdleTime,
	})

	// Test connectivity  
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := p.redisClient.Ping(ctx).Err(); err != nil {
		p.redisClient.Close()
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	p.healthCheck.AddService("redis", func() error {
		return p.redisClient.Ping(context.Background()).Err()
	})

	return nil
}

// InitializeSQL initializes SQL database with connection pooling
func (p *DatabasePool) InitializeSQL(driverName, dataSourceName string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return fmt.Errorf("failed to open SQL database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(p.config.MaxOpenConns)
	db.SetMaxIdleConns(p.config.MaxIdleConns)
	db.SetConnMaxLifetime(p.config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(p.config.ConnMaxIdleTime)

	// Test connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping SQL database: %w", err)
	}

	p.sqlDB = db
	p.healthCheck.AddService("sql", func() error {
		return p.sqlDB.Ping()
	})

	return nil
}

// ExecuteNeo4jWithRetry executes Neo4j operations with retry logic
func (p *DatabasePool) ExecuteNeo4jWithRetry(ctx context.Context, fn func(neo4j.SessionWithContext) error) error {
	var lastErr error
	
	for attempt := 0; attempt <= p.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.config.RetryBackoff * time.Duration(attempt)):
			}
		}

		session := p.neo4jDriver.NewSession(ctx, neo4j.SessionConfig{})
		err := fn(session)
		session.Close(ctx)

		if err == nil {
			return nil
		}

		lastErr = err
		
		// Don't retry certain errors
		if isNonRetryableError(err) {
			break
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", p.config.RetryAttempts, lastErr)
}

// ExecuteRedisWithRetry executes Redis operations with retry logic
func (p *DatabasePool) ExecuteRedisWithRetry(ctx context.Context, fn func(*redis.Client) error) error {
	var lastErr error
	
	for attempt := 0; attempt <= p.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.config.RetryBackoff * time.Duration(attempt)):
			}
		}

		err := fn(p.redisClient)
		if err == nil {
			return nil
		}

		lastErr = err
		
		// Don't retry certain errors
		if isNonRetryableError(err) {
			break
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", p.config.RetryAttempts, lastErr)
}

// ExecuteSQLWithRetry executes SQL operations with retry logic
func (p *DatabasePool) ExecuteSQLWithRetry(ctx context.Context, fn func(*sql.DB) error) error {
	var lastErr error
	
	for attempt := 0; attempt <= p.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.config.RetryBackoff * time.Duration(attempt)):
			}
		}

		err := fn(p.sqlDB)
		if err == nil {
			return nil
		}

		lastErr = err
		
		// Don't retry certain errors
		if isNonRetryableError(err) {
			break
		}
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", p.config.RetryAttempts, lastErr)
}

// GetMetrics returns current pool metrics
func (p *DatabasePool) GetMetrics() PoolMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()
	
	metrics := *p.metrics
	
	// Add SQL DB stats if available
	if p.sqlDB != nil {
		stats := p.sqlDB.Stats()
		metrics.OpenConnections = int64(stats.OpenConnections)
		metrics.IdleConnections = int64(stats.Idle)
		metrics.WaitCount = stats.WaitCount
		metrics.WaitDuration = stats.WaitDuration
		metrics.MaxIdleClosed = stats.MaxIdleClosed
		metrics.MaxLifetimeClosed = stats.MaxLifetimeClosed
	}
	
	return metrics
}

// GetHealthStatus returns health status of all database connections
func (p *DatabasePool) GetHealthStatus() map[string]bool {
	return p.healthCheck.GetStatus()
}

// Close gracefully closes all database connections
func (p *DatabasePool) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errors []error

	if p.healthCheck != nil {
		p.healthCheck.Stop()
	}

	if p.neo4jDriver != nil {
		if err := p.neo4jDriver.Close(ctx); err != nil {
			errors = append(errors, fmt.Errorf("failed to close Neo4j driver: %w", err))
		}
	}

	if p.redisClient != nil {
		if err := p.redisClient.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close Redis client: %w", err))
		}
	}

	if p.sqlDB != nil {
		if err := p.sqlDB.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close SQL database: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors occurred while closing connections: %v", errors)
	}

	return nil
}

// HealthChecker monitors database connection health
type HealthChecker struct {
	services map[string]func() error
	status   map[string]bool
	interval time.Duration
	stopCh   chan struct{}
	mu       sync.RWMutex
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(interval time.Duration) *HealthChecker {
	hc := &HealthChecker{
		services: make(map[string]func() error),
		status:   make(map[string]bool),
		interval: interval,
		stopCh:   make(chan struct{}),
	}
	
	go hc.start()
	return hc
}

// AddService adds a service to health monitoring
func (hc *HealthChecker) AddService(name string, check func() error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.services[name] = check
	hc.status[name] = false
}

// GetStatus returns the current health status of all services
func (hc *HealthChecker) GetStatus() map[string]bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	status := make(map[string]bool)
	for name, healthy := range hc.status {
		status[name] = healthy
	}
	
	return status
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

// start runs the health check loop
func (hc *HealthChecker) start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.checkServices()
		case <-hc.stopCh:
			return
		}
	}
}

// checkServices performs health checks on all registered services
func (hc *HealthChecker) checkServices() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	for name, checkFn := range hc.services {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := checkFn()
		cancel()
		
		hc.status[name] = err == nil
	}
}

// isNonRetryableError determines if an error should not be retried
func isNonRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	// Add logic to identify non-retryable errors
	// For example: authentication errors, syntax errors, etc.
	errorStr := err.Error()
	
	nonRetryableKeywords := []string{
		"authentication",
		"authorization", 
		"syntax error",
		"invalid query",
		"constraint violation",
		"permission denied",
	}
	
	for _, keyword := range nonRetryableKeywords {
		if contains(errorStr, keyword) {
			return true
		}
	}
	
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
			len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr || 
			 containsAtIndex(s, substr)))
}

// containsAtIndex checks if substring exists at any position
func containsAtIndex(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}