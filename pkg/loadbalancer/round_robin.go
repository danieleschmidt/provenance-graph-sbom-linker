package loadbalancer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// LoadBalancer defines the interface for load balancing
type LoadBalancer interface {
	AddBackend(backend *Backend) error
	RemoveBackend(url string) error
	GetBackend() (*Backend, error)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	GetHealthyBackends() []*Backend
	Start(ctx context.Context) error
	Stop() error
}

// Backend represents a backend server
type Backend struct {
	URL          *url.URL           `json:"url"`
	Weight       int                `json:"weight"`
	IsHealthy    bool               `json:"is_healthy"`
	ActiveConns  int64              `json:"active_connections"`
	TotalReqs    int64              `json:"total_requests"`
	FailedReqs   int64              `json:"failed_requests"`
	ResponseTime time.Duration      `json:"response_time"`
	LastCheck    time.Time          `json:"last_check"`
	Metadata     map[string]string  `json:"metadata,omitempty"`
	Proxy        *httputil.ReverseProxy
	mutex        sync.RWMutex
}

// RoundRobinLoadBalancer implements round-robin load balancing
type RoundRobinLoadBalancer struct {
	backends      []*Backend
	current       uint64
	mutex         sync.RWMutex
	healthChecker *HealthChecker
	metrics       *monitoring.MetricsCollector
	logger        *logger.StructuredLogger
	config        *LoadBalancerConfig
	running       bool
}

// LoadBalancerConfig contains load balancer configuration
type LoadBalancerConfig struct {
	HealthCheckInterval  time.Duration `json:"health_check_interval"`
	HealthCheckTimeout   time.Duration `json:"health_check_timeout"`
	HealthCheckPath      string        `json:"health_check_path"`
	MaxRetries          int           `json:"max_retries"`
	RetryDelay          time.Duration `json:"retry_delay"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout"`
}

// HealthChecker manages backend health checking
type HealthChecker struct {
	config    *LoadBalancerConfig
	backends  []*Backend
	logger    *logger.StructuredLogger
	metrics   *monitoring.MetricsCollector
	stopCh    chan bool
	mutex     sync.RWMutex
}

// NewRoundRobinLoadBalancer creates a new round-robin load balancer
func NewRoundRobinLoadBalancer(config *LoadBalancerConfig, metrics *monitoring.MetricsCollector) *RoundRobinLoadBalancer {
	if config == nil {
		config = &LoadBalancerConfig{
			HealthCheckInterval: 30 * time.Second,
			HealthCheckTimeout:  5 * time.Second,
			HealthCheckPath:     "/health",
			MaxRetries:         3,
			RetryDelay:         time.Second,
			ConnectionTimeout:  10 * time.Second,
			IdleConnTimeout:    90 * time.Second,
		}
	}

	return &RoundRobinLoadBalancer{
		backends: make([]*Backend, 0),
		config:   config,
		metrics:  metrics,
		logger:   logger.NewStructuredLogger("info", "json"),
	}
}

// AddBackend adds a backend to the load balancer
func (lb *RoundRobinLoadBalancer) AddBackend(backend *Backend) error {
	if backend == nil || backend.URL == nil {
		return fmt.Errorf("invalid backend")
	}

	// Create reverse proxy for the backend
	backend.Proxy = httputil.NewSingleHostReverseProxy(backend.URL)
	backend.Proxy.Transport = &http.Transport{
		ResponseHeaderTimeout: lb.config.ConnectionTimeout,
		IdleConnTimeout:       lb.config.IdleConnTimeout,
	}

	// Set default weight
	if backend.Weight <= 0 {
		backend.Weight = 1
	}

	// Initialize metadata
	if backend.Metadata == nil {
		backend.Metadata = make(map[string]string)
	}

	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// Check if backend already exists
	for _, existing := range lb.backends {
		if existing.URL.String() == backend.URL.String() {
			return fmt.Errorf("backend already exists: %s", backend.URL.String())
		}
	}

	lb.backends = append(lb.backends, backend)

	lb.logger.Info("backend_added", map[string]interface{}{
		"url":    backend.URL.String(),
		"weight": backend.Weight,
	})

	// Update health checker
	if lb.healthChecker != nil {
		lb.healthChecker.addBackend(backend)
	}

	return nil
}

// RemoveBackend removes a backend from the load balancer
func (lb *RoundRobinLoadBalancer) RemoveBackend(urlStr string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	for i, backend := range lb.backends {
		if backend.URL.String() == urlStr {
			// Remove from slice
			lb.backends = append(lb.backends[:i], lb.backends[i+1:]...)
			
			lb.logger.Info("backend_removed", map[string]interface{}{
				"url": urlStr,
			})

			// Update health checker
			if lb.healthChecker != nil {
				lb.healthChecker.removeBackend(urlStr)
			}

			return nil
		}
	}

	return fmt.Errorf("backend not found: %s", urlStr)
}

// GetBackend returns the next available backend using round-robin
func (lb *RoundRobinLoadBalancer) GetBackend() (*Backend, error) {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	if len(lb.backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	// Filter healthy backends
	healthyBackends := make([]*Backend, 0)
	for _, backend := range lb.backends {
		if backend.IsHealthy {
			healthyBackends = append(healthyBackends, backend)
		}
	}

	if len(healthyBackends) == 0 {
		// Fallback to all backends if none are healthy
		healthyBackends = lb.backends
		lb.logger.Warn("no_healthy_backends", map[string]interface{}{
			"total_backends": len(lb.backends),
		})
	}

	// Round-robin selection with weight consideration
	totalWeight := 0
	for _, backend := range healthyBackends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		totalWeight = len(healthyBackends)
		for _, backend := range healthyBackends {
			backend.Weight = 1
		}
	}

	// Get next backend based on weighted round-robin
	next := atomic.AddUint64(&lb.current, 1)
	index := int(next) % totalWeight

	currentWeight := 0
	for _, backend := range healthyBackends {
		currentWeight += backend.Weight
		if index < currentWeight {
			return backend, nil
		}
	}

	// Fallback to first backend
	return healthyBackends[0], nil
}

// ServeHTTP handles HTTP requests with load balancing
func (lb *RoundRobinLoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	// Get backend
	backend, err := lb.GetBackend()
	if err != nil {
		lb.logger.Error("no_backend_available", map[string]interface{}{
			"error": err.Error(),
			"path":  r.URL.Path,
		})
		
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Track active connection
	atomic.AddInt64(&backend.ActiveConns, 1)
	defer atomic.AddInt64(&backend.ActiveConns, -1)

	// Track total requests
	atomic.AddInt64(&backend.TotalReqs, 1)

	// Set up response writer wrapper to capture status
	wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: 200}

	// Serve request with retries
	for attempt := 0; attempt <= lb.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Get different backend for retry
			retryBackend, retryErr := lb.GetBackend()
			if retryErr != nil {
				break
			}
			backend = retryBackend
			
			// Wait before retry
			time.Sleep(lb.config.RetryDelay)
			
			lb.logger.Warn("request_retry", map[string]interface{}{
				"attempt":     attempt,
				"backend_url": backend.URL.String(),
				"path":        r.URL.Path,
			})
		}

		// Create request context with timeout
		ctx, cancel := context.WithTimeout(r.Context(), lb.config.ConnectionTimeout)
		r = r.WithContext(ctx)

		// Serve the request
		backend.Proxy.ServeHTTP(wrapper, r)
		cancel()

		// Check if request was successful
		if wrapper.statusCode < 500 {
			break
		} else {
			atomic.AddInt64(&backend.FailedReqs, 1)
		}
	}

	// Record metrics
	duration := time.Since(startTime)
	backend.mutex.Lock()
	backend.ResponseTime = duration
	backend.mutex.Unlock()

	if lb.metrics != nil {
		lb.metrics.RecordTiming("loadbalancer_request_duration_ms", duration, map[string]string{
			"backend": backend.URL.Host,
			"status":  fmt.Sprintf("%d", wrapper.statusCode),
		})
		
		lb.metrics.RecordCounter("loadbalancer_requests_total", 1, map[string]string{
			"backend": backend.URL.Host,
			"status":  fmt.Sprintf("%d", wrapper.statusCode),
		})
	}

	// Log request completion
	lb.logger.Info("request_completed", map[string]interface{}{
		"backend_url":   backend.URL.String(),
		"status":        wrapper.statusCode,
		"duration_ms":   duration.Milliseconds(),
		"path":          r.URL.Path,
		"method":        r.Method,
	})
}

// GetHealthyBackends returns all healthy backends
func (lb *RoundRobinLoadBalancer) GetHealthyBackends() []*Backend {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	healthyBackends := make([]*Backend, 0)
	for _, backend := range lb.backends {
		if backend.IsHealthy {
			healthyBackends = append(healthyBackends, backend)
		}
	}

	return healthyBackends
}

// Start starts the load balancer and health checker
func (lb *RoundRobinLoadBalancer) Start(ctx context.Context) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if lb.running {
		return fmt.Errorf("load balancer already running")
	}

	lb.running = true

	// Start health checker
	lb.healthChecker = NewHealthChecker(lb.config, lb.backends, lb.metrics)
	if err := lb.healthChecker.Start(ctx); err != nil {
		lb.running = false
		return fmt.Errorf("failed to start health checker: %w", err)
	}

	lb.logger.Info("loadbalancer_started", map[string]interface{}{
		"backends_count": len(lb.backends),
	})

	return nil
}

// Stop stops the load balancer
func (lb *RoundRobinLoadBalancer) Stop() error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if !lb.running {
		return nil
	}

	lb.running = false

	if lb.healthChecker != nil {
		lb.healthChecker.Stop()
	}

	lb.logger.Info("loadbalancer_stopped", map[string]interface{}{
		"backends_count": len(lb.backends),
	})

	return nil
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config *LoadBalancerConfig, backends []*Backend, metrics *monitoring.MetricsCollector) *HealthChecker {
	return &HealthChecker{
		config:   config,
		backends: backends,
		metrics:  metrics,
		logger:   logger.NewStructuredLogger("info", "json"),
		stopCh:   make(chan bool),
	}
}

// Start starts the health checker
func (hc *HealthChecker) Start(ctx context.Context) error {
	go hc.run(ctx)
	return nil
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

// run runs the health checking loop
func (hc *HealthChecker) run(ctx context.Context) {
	ticker := time.NewTicker(hc.config.HealthCheckInterval)
	defer ticker.Stop()

	// Initial health check
	hc.checkAllBackends()

	for {
		select {
		case <-ticker.C:
			hc.checkAllBackends()
		case <-hc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// checkAllBackends checks the health of all backends
func (hc *HealthChecker) checkAllBackends() {
	hc.mutex.RLock()
	backends := make([]*Backend, len(hc.backends))
	copy(backends, hc.backends)
	hc.mutex.RUnlock()

	for _, backend := range backends {
		go hc.checkBackend(backend)
	}
}

// checkBackend checks the health of a single backend
func (hc *HealthChecker) checkBackend(backend *Backend) {
	startTime := time.Now()
	
	// Create health check URL
	healthURL := *backend.URL
	healthURL.Path = hc.config.HealthCheckPath

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: hc.config.HealthCheckTimeout,
	}

	// Perform health check
	resp, err := client.Get(healthURL.String())
	
	backend.mutex.Lock()
	backend.LastCheck = time.Now()
	
	if err != nil || resp.StatusCode >= 400 {
		backend.IsHealthy = false
		if err != nil {
			hc.logger.Warn("backend_health_check_failed", map[string]interface{}{
				"backend_url": backend.URL.String(),
				"error":       err.Error(),
			})
		} else {
			resp.Body.Close()
			hc.logger.Warn("backend_health_check_failed", map[string]interface{}{
				"backend_url": backend.URL.String(),
				"status_code": resp.StatusCode,
			})
		}
	} else {
		backend.IsHealthy = true
		resp.Body.Close()
		hc.logger.Debug("backend_health_check_success", map[string]interface{}{
			"backend_url": backend.URL.String(),
		})
	}
	
	backend.mutex.Unlock()

	// Record metrics
	if hc.metrics != nil {
		duration := time.Since(startTime)
		hc.metrics.RecordTiming("health_check_duration_ms", duration, map[string]string{
			"backend": backend.URL.Host,
			"healthy": fmt.Sprintf("%t", backend.IsHealthy),
		})
	}
}

// addBackend adds a backend to the health checker
func (hc *HealthChecker) addBackend(backend *Backend) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.backends = append(hc.backends, backend)
}

// removeBackend removes a backend from the health checker
func (hc *HealthChecker) removeBackend(urlStr string) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	
	for i, backend := range hc.backends {
		if backend.URL.String() == urlStr {
			hc.backends = append(hc.backends[:i], hc.backends[i+1:]...)
			break
		}
	}
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWrapper) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = 200
	}
	return w.ResponseWriter.Write(data)
}