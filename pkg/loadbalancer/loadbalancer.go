package loadbalancer

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

type Algorithm string

const (
	RoundRobinAlgorithm     Algorithm = "round_robin"
	WeightedRoundRobin      Algorithm = "weighted_round_robin"
	LeastConnectionsAlgorithm Algorithm = "least_connections"
	ResourceBasedAlgorithm  Algorithm = "resource_based"
	IPHashAlgorithm         Algorithm = "ip_hash"
)

type CircuitBreakerConfig struct {
	FailureThreshold         int           `yaml:"failure_threshold"`
	RecoveryTimeout          time.Duration `yaml:"recovery_timeout"`
	SuccessThreshold         int           `yaml:"success_threshold"`
	RequestVolumeThreshold   int           `yaml:"request_volume_threshold"`
	ErrorPercentageThreshold float64       `yaml:"error_percentage_threshold"`
}

type RateLimitConfig struct {
	RequestsPerSecond int `yaml:"requests_per_second"`
	BurstSize         int `yaml:"burst_size"`
}

type LoadBalancerConfig struct {
	Algorithm               Algorithm            `yaml:"algorithm"`
	HealthCheckInterval     time.Duration        `yaml:"health_check_interval"`
	HealthCheckTimeout      time.Duration        `yaml:"health_check_timeout"`
	HealthCheckPath         string               `yaml:"health_check_path"`
	MaxRetries              int                  `yaml:"max_retries"`
	RetryDelay              time.Duration        `yaml:"retry_delay"`
	CircuitBreakerConfig    CircuitBreakerConfig `yaml:"circuit_breaker"`
	RateLimitConfig         RateLimitConfig      `yaml:"rate_limit"`
	AutoScalingEnabled      bool                 `yaml:"auto_scaling_enabled"`
	PredictiveScaling       bool                 `yaml:"predictive_scaling"`
	TrafficAnalysis         bool                 `yaml:"traffic_analysis"`
	SessionAffinity         bool                 `yaml:"session_affinity"`
	WeightedRouting         bool                 `yaml:"weighted_routing"`
}

type BackendHealth struct {
	URL           string    `json:"url"`
	Healthy       bool      `json:"healthy"`
	ResponseTime  time.Duration `json:"response_time"`
	LastCheck     time.Time `json:"last_check"`
	FailureCount  int       `json:"failure_count"`
	SuccessCount  int       `json:"success_count"`
}

type GeographicLocation struct {
	Region string `json:"region"`
	Zone   string `json:"zone"`
}

type Backend struct {
	URL        string              `json:"url"`
	Weight     int                 `json:"weight"`
	Location   *GeographicLocation `json:"location"`
	Health     BackendHealth       `json:"health"`
	mu         sync.RWMutex
}

type IntelligentLoadBalancer struct {
	config           LoadBalancerConfig
	backends         []*Backend
	currentIndex     int
	metricsCollector *monitoring.MetricsCollector
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	mu               sync.RWMutex
}

func NewIntelligentLoadBalancer(config LoadBalancerConfig, metricsCollector *monitoring.MetricsCollector) *IntelligentLoadBalancer {
	return &IntelligentLoadBalancer{
		config:           config,
		backends:         make([]*Backend, 0),
		metricsCollector: metricsCollector,
	}
}

func (lb *IntelligentLoadBalancer) AddBackend(url string, weight int, location *GeographicLocation) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	backend := &Backend{
		URL:      url,
		Weight:   weight,
		Location: location,
		Health: BackendHealth{
			URL:       url,
			Healthy:   true,
			LastCheck: time.Now(),
		},
	}
	
	lb.backends = append(lb.backends, backend)
	return nil
}

func (lb *IntelligentLoadBalancer) Start(ctx context.Context) error {
	lb.ctx, lb.cancel = context.WithCancel(ctx)
	
	// Start health checking
	lb.wg.Add(1)
	go lb.healthCheckLoop()
	
	return nil
}

func (lb *IntelligentLoadBalancer) Stop() {
	if lb.cancel != nil {
		lb.cancel()
	}
	lb.wg.Wait()
}

func (lb *IntelligentLoadBalancer) healthCheckLoop() {
	defer lb.wg.Done()
	
	ticker := time.NewTicker(lb.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			lb.performHealthChecks()
		case <-lb.ctx.Done():
			return
		}
	}
}

func (lb *IntelligentLoadBalancer) performHealthChecks() {
	lb.mu.RLock()
	backends := make([]*Backend, len(lb.backends))
	copy(backends, lb.backends)
	lb.mu.RUnlock()
	
	for _, backend := range backends {
		go lb.checkBackendHealth(backend)
	}
}

func (lb *IntelligentLoadBalancer) checkBackendHealth(backend *Backend) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	
	start := time.Now()
	client := &http.Client{
		Timeout: lb.config.HealthCheckTimeout,
	}
	
	healthURL := backend.URL + lb.config.HealthCheckPath
	resp, err := client.Get(healthURL)
	
	responseTime := time.Since(start)
	backend.Health.ResponseTime = responseTime
	backend.Health.LastCheck = time.Now()
	
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		backend.Health.Healthy = false
		backend.Health.FailureCount++
	} else {
		backend.Health.Healthy = true
		backend.Health.SuccessCount++
		backend.Health.FailureCount = 0
	}
	
	if resp != nil {
		resp.Body.Close()
	}
}

func (lb *IntelligentLoadBalancer) GetHealthyBackends() []*Backend {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	var healthy []*Backend
	for _, backend := range lb.backends {
		backend.mu.RLock()
		if backend.Health.Healthy {
			healthy = append(healthy, backend)
		}
		backend.mu.RUnlock()
	}
	
	return healthy
}

func (lb *IntelligentLoadBalancer) SelectBackend(clientIP string) (*Backend, error) {
	healthy := lb.GetHealthyBackends()
	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy backends available")
	}
	
	switch lb.config.Algorithm {
	case RoundRobinAlgorithm:
		return lb.roundRobinSelect(healthy), nil
	case WeightedRoundRobin:
		return lb.weightedRoundRobinSelect(healthy), nil
	case LeastConnectionsAlgorithm:
		return lb.leastConnectionsSelect(healthy), nil
	case ResourceBasedAlgorithm:
		return lb.resourceBasedSelect(healthy), nil
	case IPHashAlgorithm:
		return lb.ipHashSelect(healthy, clientIP), nil
	default:
		return lb.roundRobinSelect(healthy), nil
	}
}

func (lb *IntelligentLoadBalancer) roundRobinSelect(backends []*Backend) *Backend {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	if len(backends) == 0 {
		return nil
	}
	
	backend := backends[lb.currentIndex%len(backends)]
	lb.currentIndex++
	return backend
}

func (lb *IntelligentLoadBalancer) weightedRoundRobinSelect(backends []*Backend) *Backend {
	// Simplified weighted selection - select based on weight
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}
	
	if totalWeight == 0 {
		return lb.roundRobinSelect(backends)
	}
	
	// For simplicity, return the backend with highest weight
	var selected *Backend
	maxWeight := 0
	for _, backend := range backends {
		if backend.Weight > maxWeight {
			maxWeight = backend.Weight
			selected = backend
		}
	}
	
	return selected
}

func (lb *IntelligentLoadBalancer) leastConnectionsSelect(backends []*Backend) *Backend {
	// For simplicity, return first backend (connections not tracked yet)
	if len(backends) > 0 {
		return backends[0]
	}
	return nil
}

func (lb *IntelligentLoadBalancer) resourceBasedSelect(backends []*Backend) *Backend {
	// Select backend with best response time
	var best *Backend
	bestTime := time.Hour
	
	for _, backend := range backends {
		backend.mu.RLock()
		responseTime := backend.Health.ResponseTime
		backend.mu.RUnlock()
		
		if responseTime < bestTime {
			bestTime = responseTime
			best = backend
		}
	}
	
	if best != nil {
		return best
	}
	
	return lb.roundRobinSelect(backends)
}

func (lb *IntelligentLoadBalancer) ipHashSelect(backends []*Backend, clientIP string) *Backend {
	// Simple hash-based selection
	hash := 0
	for _, char := range clientIP {
		hash += int(char)
	}
	
	index := hash % len(backends)
	return backends[index]
}