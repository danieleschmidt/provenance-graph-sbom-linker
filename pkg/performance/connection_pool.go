package performance

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionPool manages a pool of reusable connections
type ConnectionPool struct {
	mu          sync.RWMutex
	connections chan Connection
	factory     ConnectionFactory
	cleanup     ConnectionCleanup
	
	// Pool configuration
	minConnections int
	maxConnections int
	maxIdleTime    time.Duration
	
	// Pool statistics
	totalConnections    int64
	activeConnections   int64
	createdConnections  int64
	closedConnections   int64
	
	// Pool state
	closed bool
}

// Connection represents a pooled connection
type Connection interface {
	IsValid() bool
	Close() error
	LastUsed() time.Time
}

// ConnectionFactory creates new connections
type ConnectionFactory func(ctx context.Context) (Connection, error)

// ConnectionCleanup cleans up expired connections
type ConnectionCleanup func(Connection) error

// PoolConfig configures the connection pool
type PoolConfig struct {
	MinConnections int
	MaxConnections int
	MaxIdleTime    time.Duration
	CleanupInterval time.Duration
}

// DefaultPoolConfig returns a sensible default configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MinConnections:  2,
		MaxConnections:  10,
		MaxIdleTime:     5 * time.Minute,
		CleanupInterval: time.Minute,
	}
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(factory ConnectionFactory, cleanup ConnectionCleanup, config *PoolConfig) (*ConnectionPool, error) {
	if factory == nil {
		return nil, fmt.Errorf("connection factory is required")
	}
	
	if config == nil {
		config = DefaultPoolConfig()
	}
	
	pool := &ConnectionPool{
		connections:    make(chan Connection, config.MaxConnections),
		factory:        factory,
		cleanup:        cleanup,
		minConnections: config.MinConnections,
		maxConnections: config.MaxConnections,
		maxIdleTime:    config.MaxIdleTime,
	}
	
	return pool, nil
}

// Initialize pre-fills the pool with minimum connections
func (p *ConnectionPool) Initialize(ctx context.Context) error {
	for i := 0; i < p.minConnections; i++ {
		conn, err := p.createConnection(ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize connection %d: %w", i, err)
		}
		
		select {
		case p.connections <- conn:
		default:
			conn.Close()
			return fmt.Errorf("failed to add connection to pool")
		}
	}
	
	return nil
}

// Get retrieves a connection from the pool
func (p *ConnectionPool) Get(ctx context.Context) (Connection, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, fmt.Errorf("connection pool is closed")
	}
	p.mu.RUnlock()
	
	// Try to get an existing connection
	select {
	case conn := <-p.connections:
		if conn.IsValid() && time.Since(conn.LastUsed()) < p.maxIdleTime {
			atomic.AddInt64(&p.activeConnections, 1)
			return conn, nil
		} else {
			// Connection is invalid or expired, clean it up
			if p.cleanup != nil {
				p.cleanup(conn)
			} else {
				conn.Close()
			}
			atomic.AddInt64(&p.closedConnections, 1)
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// No connections available, try to create a new one
	}
	
	// Create a new connection if we haven't reached the limit
	totalConns := atomic.LoadInt64(&p.totalConnections)
	if totalConns < int64(p.maxConnections) {
		conn, err := p.createConnection(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create new connection: %w", err)
		}
		
		atomic.AddInt64(&p.activeConnections, 1)
		return conn, nil
	}
	
	// Wait for an available connection
	select {
	case conn := <-p.connections:
		if conn.IsValid() && time.Since(conn.LastUsed()) < p.maxIdleTime {
			atomic.AddInt64(&p.activeConnections, 1)
			return conn, nil
		} else {
			// Connection is invalid, try again
			if p.cleanup != nil {
				p.cleanup(conn)
			} else {
				conn.Close()
			}
			atomic.AddInt64(&p.closedConnections, 1)
			return p.Get(ctx) // Recursive call to try again
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(conn Connection) error {
	if conn == nil {
		return fmt.Errorf("cannot put nil connection")
	}
	
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		conn.Close()
		return fmt.Errorf("connection pool is closed")
	}
	p.mu.RUnlock()
	
	atomic.AddInt64(&p.activeConnections, -1)
	
	if !conn.IsValid() {
		if p.cleanup != nil {
			p.cleanup(conn)
		} else {
			conn.Close()
		}
		atomic.AddInt64(&p.closedConnections, 1)
		return nil
	}
	
	select {
	case p.connections <- conn:
		return nil
	default:
		// Pool is full, close the connection
		conn.Close()
		atomic.AddInt64(&p.closedConnections, 1)
		return nil
	}
}

// Close closes all connections and shuts down the pool
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return nil
	}
	
	p.closed = true
	
	// Close all connections in the pool
	close(p.connections)
	for conn := range p.connections {
		if p.cleanup != nil {
			p.cleanup(conn)
		} else {
			conn.Close()
		}
		atomic.AddInt64(&p.closedConnections, 1)
	}
	
	return nil
}

// Stats returns current pool statistics
func (p *ConnectionPool) Stats() PoolStats {
	return PoolStats{
		TotalConnections:    atomic.LoadInt64(&p.totalConnections),
		ActiveConnections:   atomic.LoadInt64(&p.activeConnections),
		IdleConnections:     int64(len(p.connections)),
		CreatedConnections:  atomic.LoadInt64(&p.createdConnections),
		ClosedConnections:   atomic.LoadInt64(&p.closedConnections),
		MaxConnections:      int64(p.maxConnections),
		MinConnections:      int64(p.minConnections),
	}
}

// createConnection creates a new connection and updates statistics
func (p *ConnectionPool) createConnection(ctx context.Context) (Connection, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	
	atomic.AddInt64(&p.totalConnections, 1)
	atomic.AddInt64(&p.createdConnections, 1)
	
	return conn, nil
}

// StartCleanup starts a background goroutine to clean up expired connections
func (p *ConnectionPool) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.cleanupExpiredConnections()
			}
		}
	}()
}

// cleanupExpiredConnections removes expired connections from the pool
func (p *ConnectionPool) cleanupExpiredConnections() {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()
	
	// Check connections without blocking
	var validConnections []Connection
	poolSize := len(p.connections)
	
	for i := 0; i < poolSize; i++ {
		select {
		case conn := <-p.connections:
			if conn.IsValid() && time.Since(conn.LastUsed()) < p.maxIdleTime {
				validConnections = append(validConnections, conn)
			} else {
				if p.cleanup != nil {
					p.cleanup(conn)
				} else {
					conn.Close()
				}
				atomic.AddInt64(&p.closedConnections, 1)
				atomic.AddInt64(&p.totalConnections, -1)
			}
		default:
			break
		}
	}
	
	// Put valid connections back
	for _, conn := range validConnections {
		select {
		case p.connections <- conn:
		default:
			// Pool is full, close the connection
			conn.Close()
			atomic.AddInt64(&p.closedConnections, 1)
			atomic.AddInt64(&p.totalConnections, -1)
		}
	}
}

// PoolStats represents connection pool statistics
type PoolStats struct {
	TotalConnections    int64 `json:"total_connections"`
	ActiveConnections   int64 `json:"active_connections"`
	IdleConnections     int64 `json:"idle_connections"`
	CreatedConnections  int64 `json:"created_connections"`
	ClosedConnections   int64 `json:"closed_connections"`
	MaxConnections      int64 `json:"max_connections"`
	MinConnections      int64 `json:"min_connections"`
}

// UtilizationPercent returns the current pool utilization as a percentage
func (s PoolStats) UtilizationPercent() float64 {
	if s.MaxConnections == 0 {
		return 0
	}
	return float64(s.ActiveConnections) / float64(s.MaxConnections) * 100
}

// IsHealthy returns true if the pool is operating within healthy parameters
func (s PoolStats) IsHealthy() bool {
	utilization := s.UtilizationPercent()
	return utilization < 90 && s.TotalConnections > 0
}