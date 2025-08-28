package resilience

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthStatus represents the health state of a component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheck represents a health check for a component
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) HealthCheckResult
}

// HealthCheckResult contains the result of a health check
type HealthCheckResult struct {
	Name      string        `json:"name"`
	Status    HealthStatus  `json:"status"`
	Message   string        `json:"message,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
	Error     error         `json:"error,omitempty"`
}

// HealthMonitor manages health checks for multiple components
type HealthMonitor struct {
	checks    map[string]HealthCheck
	results   map[string]HealthCheckResult
	mutex     sync.RWMutex
	logger    *logrus.Logger
	interval  time.Duration
	timeout   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(logger *logrus.Logger, interval, timeout time.Duration) *HealthMonitor {
	if logger == nil {
		logger = logrus.New()
	}

	return &HealthMonitor{
		checks:   make(map[string]HealthCheck),
		results:  make(map[string]HealthCheckResult),
		logger:   logger,
		interval: interval,
		timeout:  timeout,
	}
}

// RegisterCheck registers a new health check
func (hm *HealthMonitor) RegisterCheck(check HealthCheck) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	
	hm.checks[check.Name()] = check
	hm.logger.WithField("check", check.Name()).Info("Registered health check")
}

// Start begins the health monitoring loop
func (hm *HealthMonitor) Start(ctx context.Context) error {
	hm.mutex.Lock()
	if hm.running {
		hm.mutex.Unlock()
		return fmt.Errorf("health monitor is already running")
	}
	
	hm.ctx, hm.cancel = context.WithCancel(ctx)
	hm.running = true
	hm.mutex.Unlock()
	
	go hm.monitorLoop()
	hm.logger.Info("Health monitor started")
	return nil
}

// Stop stops the health monitoring loop
func (hm *HealthMonitor) Stop() {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	
	if !hm.running {
		return
	}
	
	hm.cancel()
	hm.running = false
	hm.logger.Info("Health monitor stopped")
}

// GetOverallHealth returns the overall health status
func (hm *HealthMonitor) GetOverallHealth() HealthCheckResult {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()
	
	overallStatus := HealthStatusHealthy
	message := "All components are healthy"
	
	unhealthyCount := 0
	degradedCount := 0
	
	for _, result := range hm.results {
		switch result.Status {
		case HealthStatusUnhealthy:
			unhealthyCount++
			overallStatus = HealthStatusUnhealthy
		case HealthStatusDegraded:
			degradedCount++
			if overallStatus == HealthStatusHealthy {
				overallStatus = HealthStatusDegraded
			}
		}
	}
	
	if unhealthyCount > 0 {
		message = fmt.Sprintf("%d components are unhealthy", unhealthyCount)
		if degradedCount > 0 {
			message += fmt.Sprintf(" and %d are degraded", degradedCount)
		}
	} else if degradedCount > 0 {
		message = fmt.Sprintf("%d components are degraded", degradedCount)
	}
	
	return HealthCheckResult{
		Name:      "overall",
		Status:    overallStatus,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// GetCheckResults returns all current health check results
func (hm *HealthMonitor) GetCheckResults() map[string]HealthCheckResult {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()
	
	results := make(map[string]HealthCheckResult)
	for name, result := range hm.results {
		results[name] = result
	}
	
	return results
}

// monitorLoop runs the health checks periodically
func (hm *HealthMonitor) monitorLoop() {
	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()
	
	// Run initial check
	hm.runChecks()
	
	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			hm.runChecks()
		}
	}
}

// runChecks executes all registered health checks
func (hm *HealthMonitor) runChecks() {
	hm.mutex.RLock()
	checks := make([]HealthCheck, 0, len(hm.checks))
	for _, check := range hm.checks {
		checks = append(checks, check)
	}
	hm.mutex.RUnlock()
	
	results := make(map[string]HealthCheckResult)
	
	// Run checks concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan HealthCheckResult, len(checks))
	
	for _, check := range checks {
		wg.Add(1)
		go func(c HealthCheck) {
			defer wg.Done()
			
			ctx, cancel := context.WithTimeout(hm.ctx, hm.timeout)
			defer cancel()
			
			start := time.Now()
			result := c.Check(ctx)
			result.Duration = time.Since(start)
			result.Timestamp = time.Now()
			
			if result.Error != nil {
				hm.logger.WithError(result.Error).
					WithField("check", result.Name).
					Warn("Health check failed")
			}
			
			resultsChan <- result
		}(check)
	}
	
	wg.Wait()
	close(resultsChan)
	
	// Collect results
	for result := range resultsChan {
		results[result.Name] = result
	}
	
	// Update stored results
	hm.mutex.Lock()
	hm.results = results
	hm.mutex.Unlock()
}

// DatabaseHealthCheck checks database connectivity
type DatabaseHealthCheck struct {
	name     string
	checkFn  func(context.Context) error
}

// NewDatabaseHealthCheck creates a new database health check
func NewDatabaseHealthCheck(name string, checkFn func(context.Context) error) *DatabaseHealthCheck {
	return &DatabaseHealthCheck{
		name:    name,
		checkFn: checkFn,
	}
}

func (dhc *DatabaseHealthCheck) Name() string {
	return dhc.name
}

func (dhc *DatabaseHealthCheck) Check(ctx context.Context) HealthCheckResult {
	err := dhc.checkFn(ctx)
	if err != nil {
		return HealthCheckResult{
			Name:    dhc.name,
			Status:  HealthStatusUnhealthy,
			Message: "Database connection failed",
			Error:   err,
		}
	}
	
	return HealthCheckResult{
		Name:    dhc.name,
		Status:  HealthStatusHealthy,
		Message: "Database connection successful",
	}
}

// RedisHealthCheck checks Redis connectivity
type RedisHealthCheck struct {
	name    string
	checkFn func(context.Context) error
}

// NewRedisHealthCheck creates a new Redis health check
func NewRedisHealthCheck(name string, checkFn func(context.Context) error) *RedisHealthCheck {
	return &RedisHealthCheck{
		name:    name,
		checkFn: checkFn,
	}
}

func (rhc *RedisHealthCheck) Name() string {
	return rhc.name
}

func (rhc *RedisHealthCheck) Check(ctx context.Context) HealthCheckResult {
	err := rhc.checkFn(ctx)
	if err != nil {
		return HealthCheckResult{
			Name:    rhc.name,
			Status:  HealthStatusUnhealthy,
			Message: "Redis connection failed",
			Error:   err,
		}
	}
	
	return HealthCheckResult{
		Name:    rhc.name,
		Status:  HealthStatusHealthy,
		Message: "Redis connection successful",
	}
}