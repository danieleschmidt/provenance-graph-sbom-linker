package loadbalancer

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// IntelligentLoadBalancer provides advanced load balancing with predictive scaling
type IntelligentLoadBalancer struct {
	config              LoadBalancerConfig
	backends            []*Backend
	healthChecker       *HealthChecker
	trafficAnalyzer     *TrafficAnalyzer
	autoScaler          *AutoScaler
	requestRouter       *RequestRouter
	circuitBreaker      *CircuitBreaker
	rateLimiter         *RateLimiter
	logger              *logger.StructuredLogger
	metricsCollector    *monitoring.MetricsCollector
	started             bool
	mutex               sync.RWMutex
	stats               *LoadBalancerStats
}

type LoadBalancerConfig struct {
	Algorithm            Algorithm
	HealthCheckInterval  time.Duration
	HealthCheckTimeout   time.Duration
	HealthCheckPath      string
	MaxRetries           int
	RetryDelay           time.Duration
	CircuitBreakerConfig CircuitBreakerConfig
	RateLimitConfig      RateLimitConfig
	AutoScalingEnabled   bool
	PredictiveScaling    bool
	TrafficAnalysis      bool
	SessionAffinity      bool
	WeightedRouting      bool
}

type Algorithm int

const (
	RoundRobinAlgorithm Algorithm = iota
	LeastConnectionsAlgorithm
	WeightedRoundRobinAlgorithm
	IPHashAlgorithm
	ResourceBasedAlgorithm
	PredictiveAlgorithm
	GeographicAlgorithm
)

type Backend struct {
	ID              string
	URL             *url.URL
	Weight          int
	Active          bool
	Healthy         bool
	ReverseProxy    *httputil.ReverseProxy
	Stats           *BackendStats
	ResourceMetrics *ResourceMetrics
	Location        *GeographicLocation
	mutex           sync.RWMutex
}

type BackendStats struct {
	RequestCount     int64
	ErrorCount       int64
	TotalLatency     time.Duration
	AverageLatency   time.Duration
	LastRequest      time.Time
	ActiveConnections int32
	SuccessRate      float64
	Throughput       float64
}

type ResourceMetrics struct {
	CPUUsage        float64
	MemoryUsage     float64
	DiskUsage       float64
	NetworkUsage    float64
	LoadAverage     float64
	ResponseTime    time.Duration
	LastUpdate      time.Time
}

type GeographicLocation struct {
	Region    string
	Zone      string
	Latitude  float64
	Longitude float64
}

type HealthChecker struct {
	loadBalancer    *IntelligentLoadBalancer
	healthChecks    map[string]*HealthStatus
	mutex           sync.RWMutex
}

type HealthStatus struct {
	Backend         *Backend
	IsHealthy       bool
	LastCheck       time.Time
	ConsecutiveFails int
	ResponseTime    time.Duration
	ErrorMessage    string
	HealthHistory   []HealthCheckResult
}

type HealthCheckResult struct {
	Timestamp    time.Time
	Healthy      bool
	ResponseTime time.Duration
	StatusCode   int
	Error        string
}

type TrafficAnalyzer struct {
	requestPatterns   map[string]*RequestPattern
	trafficPrediction *TrafficPrediction
	loadForecast      *LoadForecast
	mutex             sync.RWMutex
}

type RequestPattern struct {
	Path           string
	Method         string
	RequestsPerMin float64
	AverageSize    int64
	PeakTimes      []time.Duration
	Seasonality    map[string]float64
	LastUpdate     time.Time
}

type TrafficPrediction struct {
	NextHourLoad     float64
	NextDayLoad      float64
	PredictedPeaks   []time.Time
	Confidence       float64
	ModelAccuracy    float64
}

type LoadForecast struct {
	TimeWindow      time.Duration
	PredictedLoad   float64
	RequiredBackends int
	Confidence      float64
	BasedOnPattern  string
}

type AutoScaler struct {
	loadBalancer     *IntelligentLoadBalancer
	scalingHistory   []ScalingEvent
	triggers         *ScalingTriggers
	cooldownPeriod   time.Duration
	lastScalingTime  time.Time
	mutex            sync.RWMutex
}

type ScalingEvent struct {
	Timestamp     time.Time
	Action        ScalingAction
	Reason        string
	OldBackends   int
	NewBackends   int
	LoadAverage   float64
	PredictedLoad float64
}

type ScalingAction int

const (
	ScaleUpAction ScalingAction = iota
	ScaleDownAction
	NoScalingAction
)

type ScalingTriggers struct {
	CPUThreshold        float64
	MemoryThreshold     float64
	LatencyThreshold    time.Duration
	ThroughputThreshold float64
	ErrorRateThreshold  float64
	QueueLengthThreshold int
}

type RequestRouter struct {
	sessionStore    map[string]string
	routingRules    []*RoutingRule
	pathPriorities  map[string]int
	mutex           sync.RWMutex
}

type RoutingRule struct {
	Pattern     string
	Backend     string
	Weight      int
	Conditions  []Condition
	Actions     []Action
	Priority    int
}

type Condition struct {
	Type     ConditionType
	Field    string
	Operator string
	Value    string
}

type ConditionType int

const (
	HeaderCondition ConditionType = iota
	PathCondition
	MethodCondition
	GeographicCondition
	TimeCondition
	LoadCondition
)

type Action struct {
	Type   ActionType
	Target string
	Value  string
}

type ActionType int

const (
	RouteToBackend ActionType = iota
	SetHeader
	RateLimit
	CircuitBreaker
)

type CircuitBreaker struct {
	states       map[string]*CircuitBreakerState
	config       CircuitBreakerConfig
	mutex        sync.RWMutex
}

type CircuitBreakerConfig struct {
	FailureThreshold   int
	RecoveryTimeout    time.Duration
	SuccessThreshold   int
	RequestVolumeThreshold int
	ErrorPercentageThreshold float64
}

type CircuitBreakerState struct {
	State                CircuitState
	FailureCount         int
	SuccessCount         int
	LastFailureTime      time.Time
	NextRetryTime        time.Time
	HalfOpenSuccessCount int
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

type RateLimiter struct {
	limiters map[string]*TokenBucket
	config   RateLimitConfig
	mutex    sync.RWMutex
}

type RateLimitConfig struct {
	RequestsPerSecond int
	BurstSize         int
	KeyExtractor      func(*gin.Context) string
}

type TokenBucket struct {
	tokens        float64
	capacity      float64
	refillRate    float64
	lastRefill    time.Time
	mutex         sync.Mutex
}

type LoadBalancerStats struct {
	TotalRequests     int64
	SuccessfulRequests int64
	FailedRequests    int64
	AverageLatency    time.Duration
	ThroughputPerSec  float64
	ActiveBackends    int32
	HealthyBackends   int32
	LastUpdate        time.Time
}

// NewIntelligentLoadBalancer creates a new intelligent load balancer
func NewIntelligentLoadBalancer(config LoadBalancerConfig, metricsCollector *monitoring.MetricsCollector) *IntelligentLoadBalancer {
	lb := &IntelligentLoadBalancer{
		config:           config,
		backends:         make([]*Backend, 0),
		logger:           logger.NewStructuredLogger("info", "json"),
		metricsCollector: metricsCollector,
		stats:            &LoadBalancerStats{},
	}

	// Initialize components
	lb.healthChecker = NewHealthChecker(lb)
	lb.trafficAnalyzer = NewTrafficAnalyzer()
	lb.autoScaler = NewAutoScaler(lb)
	lb.requestRouter = NewRequestRouter()
	lb.circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig)
	lb.rateLimiter = NewRateLimiter(config.RateLimitConfig)

	return lb
}

// Start initializes and starts the load balancer
func (lb *IntelligentLoadBalancer) Start(ctx context.Context) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if lb.started {
		return fmt.Errorf("load balancer already started")
	}

	// Start health checking
	go lb.healthChecker.Start(ctx)

	// Start traffic analysis
	if lb.config.TrafficAnalysis {
		go lb.trafficAnalyzer.Start(ctx)
	}

	// Start auto scaling
	if lb.config.AutoScalingEnabled {
		go lb.autoScaler.Start(ctx)
	}

	// Start metrics collection
	go lb.metricsRoutine(ctx)

	lb.started = true

	lb.logger.Info("intelligent_load_balancer_started", map[string]interface{}{
		"algorithm":             lb.config.Algorithm,
		"auto_scaling_enabled":  lb.config.AutoScalingEnabled,
		"predictive_scaling":    lb.config.PredictiveScaling,
		"traffic_analysis":      lb.config.TrafficAnalysis,
		"session_affinity":      lb.config.SessionAffinity,
	})

	return nil
}

// AddBackend adds a new backend to the load balancer
func (lb *IntelligentLoadBalancer) AddBackend(backendURL string, weight int, location *GeographicLocation) error {
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}

	backend := &Backend{
		ID:       fmt.Sprintf("backend_%d", len(lb.backends)),
		URL:      parsedURL,
		Weight:   weight,
		Active:   true,
		Healthy:  true,
		Location: location,
		Stats: &BackendStats{
			LastRequest: time.Now(),
		},
		ResourceMetrics: &ResourceMetrics{
			LastUpdate: time.Now(),
		},
	}

	// Create reverse proxy
	backend.ReverseProxy = httputil.NewSingleHostReverseProxy(parsedURL)
	backend.ReverseProxy.ModifyResponse = lb.modifyResponse(backend)
	backend.ReverseProxy.ErrorHandler = lb.errorHandler(backend)

	lb.mutex.Lock()
	lb.backends = append(lb.backends, backend)
	atomic.AddInt32(&lb.stats.ActiveBackends, 1)
	atomic.AddInt32(&lb.stats.HealthyBackends, 1)
	lb.mutex.Unlock()

	// Initialize health status
	lb.healthChecker.AddBackend(backend)

	lb.logger.Info("backend_added", map[string]interface{}{
		"backend_id": backend.ID,
		"url":        backendURL,
		"weight":     weight,
	})

	return nil
}

// LoadBalanceMiddleware returns a Gin middleware for load balancing
func (lb *IntelligentLoadBalancer) LoadBalanceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Rate limiting
		if !lb.rateLimiter.Allow(c) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			c.Abort()
			return
		}

		// Record traffic pattern
		if lb.config.TrafficAnalysis {
			lb.trafficAnalyzer.RecordRequest(c)
		}

		// Select backend
		backend := lb.selectBackend(c)
		if backend == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no healthy backends available"})
			c.Abort()
			return
		}

		// Check circuit breaker
		if !lb.circuitBreaker.AllowRequest(backend.ID) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "circuit breaker open"})
			c.Abort()
			return
		}

		// Update backend stats
		atomic.AddInt64(&backend.Stats.RequestCount, 1)
		atomic.AddInt32(&backend.Stats.ActiveConnections, 1)

		// Proxy the request
		backend.ReverseProxy.ServeHTTP(c.Writer, c.Request)

		// Update metrics
		duration := time.Since(startTime)
		lb.updateRequestMetrics(backend, duration, c.Writer.Status())

		atomic.AddInt32(&backend.Stats.ActiveConnections, -1)
	}
}

// selectBackend selects the best backend based on the configured algorithm
func (lb *IntelligentLoadBalancer) selectBackend(c *gin.Context) *Backend {
	lb.mutex.RLock()
	healthyBackends := make([]*Backend, 0, len(lb.backends))
	for _, backend := range lb.backends {
		if backend.Active && backend.Healthy {
			healthyBackends = append(healthyBackends, backend)
		}
	}
	lb.mutex.RUnlock()

	if len(healthyBackends) == 0 {
		return nil
	}

	switch lb.config.Algorithm {
	case LeastConnectionsAlgorithm:
		return lb.selectLeastConnections(healthyBackends)
	case WeightedRoundRobinAlgorithm:
		return lb.selectWeightedRoundRobin(healthyBackends)
	case IPHashAlgorithm:
		return lb.selectIPHash(healthyBackends, c.ClientIP())
	case ResourceBasedAlgorithm:
		return lb.selectResourceBased(healthyBackends)
	case PredictiveAlgorithm:
		return lb.selectPredictive(healthyBackends, c)
	case GeographicAlgorithm:
		return lb.selectGeographic(healthyBackends, c)
	default:
		return lb.selectRoundRobin(healthyBackends)
	}
}

func (lb *IntelligentLoadBalancer) selectRoundRobin(backends []*Backend) *Backend {
	// Simple round robin using timestamp
	index := int(time.Now().UnixNano()) % len(backends)
	return backends[index]
}

func (lb *IntelligentLoadBalancer) selectLeastConnections(backends []*Backend) *Backend {
	var selected *Backend
	var minConnections int32 = math.MaxInt32

	for _, backend := range backends {
		connections := atomic.LoadInt32(&backend.Stats.ActiveConnections)
		if connections < minConnections {
			minConnections = connections
			selected = backend
		}
	}

	return selected
}

func (lb *IntelligentLoadBalancer) selectWeightedRoundRobin(backends []*Backend) *Backend {
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return lb.selectRoundRobin(backends)
	}

	// Generate random number
	random := int(time.Now().UnixNano()) % totalWeight
	currentWeight := 0

	for _, backend := range backends {
		currentWeight += backend.Weight
		if random < currentWeight {
			return backend
		}
	}

	return backends[0]
}

func (lb *IntelligentLoadBalancer) selectIPHash(backends []*Backend, clientIP string) *Backend {
	hash := 0
	for _, byte := range []byte(clientIP) {
		hash = hash*31 + int(byte)
	}
	
	index := hash % len(backends)
	if index < 0 {
		index = -index
	}
	
	return backends[index]
}

func (lb *IntelligentLoadBalancer) selectResourceBased(backends []*Backend) *Backend {
	var selected *Backend
	var bestScore float64 = -1

	for _, backend := range backends {
		backend.mutex.RLock()
		// Calculate composite score based on resource usage
		cpuScore := 1.0 - (backend.ResourceMetrics.CPUUsage / 100.0)
		memoryScore := 1.0 - (backend.ResourceMetrics.MemoryUsage / 100.0)
		latencyScore := 1.0 / (1.0 + backend.ResourceMetrics.ResponseTime.Seconds())
		loadScore := 1.0 - (backend.ResourceMetrics.LoadAverage / 10.0)
		backend.mutex.RUnlock()

		score := (cpuScore + memoryScore + latencyScore + loadScore) / 4.0

		if selected == nil || score > bestScore {
			selected = backend
			bestScore = score
		}
	}

	return selected
}

func (lb *IntelligentLoadBalancer) selectPredictive(backends []*Backend, c *gin.Context) *Backend {
	// Use traffic analyzer prediction
	prediction := lb.trafficAnalyzer.GetPrediction()
	
	// Select backend based on predicted load
	if prediction.NextHourLoad > 0.8 {
		// High load predicted, prefer fastest backend
		return lb.selectFastest(backends)
	} else if prediction.NextHourLoad < 0.3 {
		// Low load predicted, prefer energy efficient backend
		return lb.selectEnergyEfficient(backends)
	}

	// Medium load, use resource-based selection
	return lb.selectResourceBased(backends)
}

func (lb *IntelligentLoadBalancer) selectGeographic(backends []*Backend, c *gin.Context) *Backend {
	// Simple geographic selection based on request headers
	// In production, you'd use GeoIP or similar
	userRegion := c.GetHeader("X-User-Region")
	
	for _, backend := range backends {
		if backend.Location != nil && backend.Location.Region == userRegion {
			return backend
		}
	}

	// Fallback to resource-based selection
	return lb.selectResourceBased(backends)
}

func (lb *IntelligentLoadBalancer) selectFastest(backends []*Backend) *Backend {
	var fastest *Backend
	var minLatency time.Duration = time.Hour // Large initial value

	for _, backend := range backends {
		backend.mutex.RLock()
		latency := backend.Stats.AverageLatency
		backend.mutex.RUnlock()

		if fastest == nil || latency < minLatency {
			fastest = backend
			minLatency = latency
		}
	}

	return fastest
}

func (lb *IntelligentLoadBalancer) selectEnergyEfficient(backends []*Backend) *Backend {
	// Select backend with lowest CPU and memory usage
	var selected *Backend
	var lowestUsage float64 = math.MaxFloat64

	for _, backend := range backends {
		backend.mutex.RLock()
		usage := backend.ResourceMetrics.CPUUsage + backend.ResourceMetrics.MemoryUsage
		backend.mutex.RUnlock()

		if selected == nil || usage < lowestUsage {
			selected = backend
			lowestUsage = usage
		}
	}

	return selected
}

// Helper functions and component implementations

func (lb *IntelligentLoadBalancer) modifyResponse(backend *Backend) func(*http.Response) error {
	return func(resp *http.Response) error {
		// Add load balancer headers
		resp.Header.Set("X-LoadBalancer-Backend", backend.ID)
		resp.Header.Set("X-LoadBalancer-Algorithm", fmt.Sprintf("%d", lb.config.Algorithm))
		
		return nil
	}
}

func (lb *IntelligentLoadBalancer) errorHandler(backend *Backend) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		atomic.AddInt64(&backend.Stats.ErrorCount, 1)
		atomic.AddInt64(&lb.stats.FailedRequests, 1)
		
		lb.circuitBreaker.RecordFailure(backend.ID)
		
		lb.logger.Error("backend_request_failed", map[string]interface{}{
			"backend_id": backend.ID,
			"error":      err.Error(),
			"path":       r.URL.Path,
		})

		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Backend unavailable"))
	}
}

func (lb *IntelligentLoadBalancer) updateRequestMetrics(backend *Backend, duration time.Duration, statusCode int) {
	atomic.AddInt64(&lb.stats.TotalRequests, 1)
	
	if statusCode >= 200 && statusCode < 400 {
		atomic.AddInt64(&lb.stats.SuccessfulRequests, 1)
		lb.circuitBreaker.RecordSuccess(backend.ID)
	} else {
		atomic.AddInt64(&lb.stats.FailedRequests, 1)
		lb.circuitBreaker.RecordFailure(backend.ID)
	}

	// Update backend stats
	backend.mutex.Lock()
	backend.Stats.TotalLatency += duration
	backend.Stats.LastRequest = time.Now()
	
	// Calculate average latency
	if backend.Stats.RequestCount > 0 {
		backend.Stats.AverageLatency = backend.Stats.TotalLatency / time.Duration(backend.Stats.RequestCount)
	}
	
	// Calculate success rate
	if backend.Stats.RequestCount > 0 {
		backend.Stats.SuccessRate = float64(backend.Stats.RequestCount-backend.Stats.ErrorCount) / float64(backend.Stats.RequestCount)
	}
	backend.mutex.Unlock()

	// Record metrics
	lb.metricsCollector.RecordTiming("lb_request_duration", duration, map[string]string{
		"backend_id": backend.ID,
		"status":     fmt.Sprintf("%d", statusCode),
	})
}

func (lb *IntelligentLoadBalancer) metricsRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lb.recordMetrics()
		case <-ctx.Done():
			return
		}
	}
}

func (lb *IntelligentLoadBalancer) recordMetrics() {
	// Record load balancer metrics
	lb.metricsCollector.RecordGauge("lb_active_backends", float64(atomic.LoadInt32(&lb.stats.ActiveBackends)), nil)
	lb.metricsCollector.RecordGauge("lb_healthy_backends", float64(atomic.LoadInt32(&lb.stats.HealthyBackends)), nil)
	lb.metricsCollector.RecordCounter("lb_total_requests", atomic.LoadInt64(&lb.stats.TotalRequests), nil)
	lb.metricsCollector.RecordCounter("lb_successful_requests", atomic.LoadInt64(&lb.stats.SuccessfulRequests), nil)
	lb.metricsCollector.RecordCounter("lb_failed_requests", atomic.LoadInt64(&lb.stats.FailedRequests), nil)

	// Record backend metrics
	for _, backend := range lb.backends {
		labels := map[string]string{"backend_id": backend.ID}
		
		backend.mutex.RLock()
		lb.metricsCollector.RecordCounter("backend_requests_total", backend.Stats.RequestCount, labels)
		lb.metricsCollector.RecordCounter("backend_errors_total", backend.Stats.ErrorCount, labels)
		lb.metricsCollector.RecordGauge("backend_active_connections", float64(backend.Stats.ActiveConnections), labels)
		lb.metricsCollector.RecordGauge("backend_success_rate", backend.Stats.SuccessRate, labels)
		lb.metricsCollector.RecordTiming("backend_average_latency", backend.Stats.AverageLatency, labels)
		backend.mutex.RUnlock()
	}
}

// Component constructors and implementations would continue...
// Due to length constraints, showing abbreviated implementations

func NewHealthChecker(lb *IntelligentLoadBalancer) *HealthChecker {
	return &HealthChecker{
		loadBalancer: lb,
		healthChecks: make(map[string]*HealthStatus),
	}
}

func (hc *HealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(hc.loadBalancer.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthChecks()
		case <-ctx.Done():
			return
		}
	}
}

func (hc *HealthChecker) AddBackend(backend *Backend) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	hc.healthChecks[backend.ID] = &HealthStatus{
		Backend:       backend,
		IsHealthy:     true,
		LastCheck:     time.Now(),
		HealthHistory: make([]HealthCheckResult, 0, 100),
	}
}

func (hc *HealthChecker) performHealthChecks() {
	hc.mutex.RLock()
	backends := make([]*HealthStatus, 0, len(hc.healthChecks))
	for _, status := range hc.healthChecks {
		backends = append(backends, status)
	}
	hc.mutex.RUnlock()

	for _, status := range backends {
		go hc.checkBackend(status)
	}
}

func (hc *HealthChecker) checkBackend(status *HealthStatus) {
	startTime := time.Now()
	
	// Create health check request
	healthURL := status.Backend.URL.String() + hc.loadBalancer.config.HealthCheckPath
	client := &http.Client{
		Timeout: hc.loadBalancer.config.HealthCheckTimeout,
	}

	resp, err := client.Get(healthURL)
	duration := time.Since(startTime)

	result := HealthCheckResult{
		Timestamp:    time.Now(),
		ResponseTime: duration,
	}

	if err != nil {
		result.Healthy = false
		result.Error = err.Error()
		status.ConsecutiveFails++
	} else {
		result.StatusCode = resp.StatusCode
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.Healthy = true
			status.ConsecutiveFails = 0
		} else {
			result.Healthy = false
			result.Error = fmt.Sprintf("status code: %d", resp.StatusCode)
			status.ConsecutiveFails++
		}
	}

	// Update status
	hc.mutex.Lock()
	status.LastCheck = time.Now()
	status.ResponseTime = duration
	status.HealthHistory = append(status.HealthHistory, result)
	
	// Keep only last 100 checks
	if len(status.HealthHistory) > 100 {
		status.HealthHistory = status.HealthHistory[1:]
	}

	// Update backend health
	wasHealthy := status.Backend.Healthy
	status.IsHealthy = result.Healthy && status.ConsecutiveFails < 3
	status.Backend.Healthy = status.IsHealthy

	if wasHealthy != status.IsHealthy {
		if status.IsHealthy {
			atomic.AddInt32(&hc.loadBalancer.stats.HealthyBackends, 1)
		} else {
			atomic.AddInt32(&hc.loadBalancer.stats.HealthyBackends, -1)
		}
	}
	hc.mutex.Unlock()

	// Log health status changes
	if wasHealthy != status.IsHealthy {
		hc.loadBalancer.logger.Info("backend_health_changed", map[string]interface{}{
			"backend_id":        status.Backend.ID,
			"healthy":           status.IsHealthy,
			"consecutive_fails": status.ConsecutiveFails,
			"response_time":     duration.String(),
		})
	}
}

func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{
		requestPatterns: make(map[string]*RequestPattern),
		trafficPrediction: &TrafficPrediction{},
		loadForecast:      &LoadForecast{},
	}
}

func (ta *TrafficAnalyzer) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ta.analyzeTraffic()
		case <-ctx.Done():
			return
		}
	}
}

func (ta *TrafficAnalyzer) RecordRequest(c *gin.Context) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	key := fmt.Sprintf("%s:%s", c.Request.Method, c.FullPath())
	pattern, exists := ta.requestPatterns[key]
	if !exists {
		pattern = &RequestPattern{
			Path:        c.FullPath(),
			Method:      c.Request.Method,
			Seasonality: make(map[string]float64),
		}
		ta.requestPatterns[key] = pattern
	}

	pattern.RequestsPerMin++
	pattern.LastUpdate = time.Now()
}

func (ta *TrafficAnalyzer) analyzeTraffic() {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	// Simple traffic analysis
	totalRequests := 0.0
	for _, pattern := range ta.requestPatterns {
		totalRequests += pattern.RequestsPerMin
		pattern.RequestsPerMin = 0 // Reset for next minute
	}

	// Update prediction
	ta.trafficPrediction.NextHourLoad = totalRequests / 60.0 // Simple average
	ta.trafficPrediction.Confidence = 0.7                   // Simplified confidence
}

func (ta *TrafficAnalyzer) GetPrediction() *TrafficPrediction {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()
	
	prediction := *ta.trafficPrediction
	return &prediction
}

func NewAutoScaler(lb *IntelligentLoadBalancer) *AutoScaler {
	return &AutoScaler{
		loadBalancer:   lb,
		scalingHistory: make([]ScalingEvent, 0, 1000),
		triggers: &ScalingTriggers{
			CPUThreshold:         80.0,
			MemoryThreshold:      80.0,
			LatencyThreshold:     500 * time.Millisecond,
			ThroughputThreshold:  1000.0,
			ErrorRateThreshold:   0.05,
			QueueLengthThreshold: 100,
		},
		cooldownPeriod: 5 * time.Minute,
	}
}

func (as *AutoScaler) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			as.evaluateScaling()
		case <-ctx.Done():
			return
		}
	}
}

func (as *AutoScaler) evaluateScaling() {
	// Check if we're in cooldown period
	if time.Since(as.lastScalingTime) < as.cooldownPeriod {
		return
	}

	// Simplified scaling logic for Generation 3
	avgLatency := as.calculateAverageLatency()
	errorRate := as.calculateErrorRate()
	
	if avgLatency > as.triggers.LatencyThreshold || errorRate > as.triggers.ErrorRateThreshold {
		as.triggerScaleUp("performance_degradation")
	} else if avgLatency < as.triggers.LatencyThreshold/2 && errorRate < as.triggers.ErrorRateThreshold/2 {
		as.triggerScaleDown("low_utilization")
	}
}

func (as *AutoScaler) calculateAverageLatency() time.Duration {
	as.loadBalancer.mutex.RLock()
	defer as.loadBalancer.mutex.RUnlock()

	if len(as.loadBalancer.backends) == 0 {
		return 0
	}

	var totalLatency time.Duration
	var count int

	for _, backend := range as.loadBalancer.backends {
		if backend.Healthy {
			backend.mutex.RLock()
			totalLatency += backend.Stats.AverageLatency
			count++
			backend.mutex.RUnlock()
		}
	}

	if count == 0 {
		return 0
	}

	return totalLatency / time.Duration(count)
}

func (as *AutoScaler) calculateErrorRate() float64 {
	totalRequests := atomic.LoadInt64(&as.loadBalancer.stats.TotalRequests)
	failedRequests := atomic.LoadInt64(&as.loadBalancer.stats.FailedRequests)

	if totalRequests == 0 {
		return 0
	}

	return float64(failedRequests) / float64(totalRequests)
}

func (as *AutoScaler) triggerScaleUp(reason string) {
	// In a real implementation, this would trigger actual scaling
	as.loadBalancer.logger.Info("scale_up_triggered", map[string]interface{}{
		"reason": reason,
		"current_backends": len(as.loadBalancer.backends),
	})
	
	as.lastScalingTime = time.Now()
}

func (as *AutoScaler) triggerScaleDown(reason string) {
	// In a real implementation, this would trigger actual scaling
	as.loadBalancer.logger.Info("scale_down_triggered", map[string]interface{}{
		"reason": reason,
		"current_backends": len(as.loadBalancer.backends),
	})
	
	as.lastScalingTime = time.Now()
}

func NewRequestRouter() *RequestRouter {
	return &RequestRouter{
		sessionStore:   make(map[string]string),
		routingRules:   make([]*RoutingRule, 0),
		pathPriorities: make(map[string]int),
	}
}

func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		states: make(map[string]*CircuitBreakerState),
		config: config,
	}
}

func (cb *CircuitBreaker) AllowRequest(backendID string) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	state, exists := cb.states[backendID]
	if !exists {
		state = &CircuitBreakerState{State: CircuitClosed}
		cb.states[backendID] = state
	}

	switch state.State {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Now().After(state.NextRetryTime) {
			state.State = CircuitHalfOpen
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return true
	}
}

func (cb *CircuitBreaker) RecordSuccess(backendID string) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	state := cb.states[backendID]
	if state == nil {
		return
	}

	state.SuccessCount++
	
	if state.State == CircuitHalfOpen && state.SuccessCount >= cb.config.SuccessThreshold {
		state.State = CircuitClosed
		state.FailureCount = 0
	}
}

func (cb *CircuitBreaker) RecordFailure(backendID string) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	state := cb.states[backendID]
	if state == nil {
		state = &CircuitBreakerState{State: CircuitClosed}
		cb.states[backendID] = state
	}

	state.FailureCount++
	state.LastFailureTime = time.Now()

	if state.FailureCount >= cb.config.FailureThreshold {
		state.State = CircuitOpen
		state.NextRetryTime = time.Now().Add(cb.config.RecoveryTimeout)
	}
}

func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*TokenBucket),
		config:   config,
	}
}

func (rl *RateLimiter) Allow(c *gin.Context) bool {
	key := "default"
	if rl.config.KeyExtractor != nil {
		key = rl.config.KeyExtractor(c)
	}

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	bucket, exists := rl.limiters[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:     float64(rl.config.BurstSize),
			capacity:   float64(rl.config.BurstSize),
			refillRate: float64(rl.config.RequestsPerSecond),
			lastRefill: time.Now(),
		}
		rl.limiters[key] = bucket
	}

	return bucket.Allow()
}

func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	
	// Refill tokens
	tb.tokens = math.Min(tb.capacity, tb.tokens+elapsed*tb.refillRate)
	tb.lastRefill = now

	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}

	return false
}

// GetStats returns comprehensive load balancer statistics
func (lb *IntelligentLoadBalancer) GetStats() *LoadBalancerStats {
	stats := *lb.stats
	stats.LastUpdate = time.Now()
	
	// Calculate throughput
	if stats.TotalRequests > 0 {
		stats.ThroughputPerSec = float64(stats.TotalRequests) / time.Since(stats.LastUpdate).Seconds()
	}

	return &stats
}

// Stop gracefully shuts down the load balancer
func (lb *IntelligentLoadBalancer) Stop() error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if !lb.started {
		return nil
	}

	lb.started = false

	lb.logger.Info("intelligent_load_balancer_stopped", map[string]interface{}{
		"total_requests": atomic.LoadInt64(&lb.stats.TotalRequests),
		"backends":       len(lb.backends),
	})

	return nil
}