package monitoring

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SelfHealingMetrics provides metrics for self-healing system components
type SelfHealingMetrics struct {
	logger     *logrus.Logger
	mu         sync.RWMutex
	components map[string]*ComponentHealth
}

// ComponentHealth represents the health status of a system component
type ComponentHealth struct {
	ComponentID string    `json:"component_id"`
	HealthStatus int       `json:"health_status"` // 0=healthy, 1=degraded, 2=unhealthy, 3=critical
	ErrorRate    float64   `json:"error_rate"`
	LatencyMs    float64   `json:"latency_ms"`
	LastUpdate   time.Time `json:"last_update"`
}

// NewSelfHealingMetrics creates a new self-healing metrics collector
func NewSelfHealingMetrics(logger *logrus.Logger) (*SelfHealingMetrics, error) {
	return &SelfHealingMetrics{
		logger:     logger,
		components: make(map[string]*ComponentHealth),
	}, nil
}

// UpdateComponentHealth updates the health status of a component
func (shm *SelfHealingMetrics) UpdateComponentHealth(ctx context.Context, componentID string, healthStatus int, errorRate float64, latencyMs float64) {
	shm.mu.Lock()
	defer shm.mu.Unlock()
	
	shm.components[componentID] = &ComponentHealth{
		ComponentID:  componentID,
		HealthStatus: healthStatus,
		ErrorRate:    errorRate,
		LatencyMs:    latencyMs,
		LastUpdate:   time.Now(),
	}
	
	shm.logger.WithFields(logrus.Fields{
		"component_id":   componentID,
		"health_status":  healthStatus,
		"error_rate":     errorRate,
		"latency_ms":     latencyMs,
	}).Debug("Updated component health")
}

// GetComponentHealth returns the health status of a specific component
func (shm *SelfHealingMetrics) GetComponentHealth(componentID string) *ComponentHealth {
	shm.mu.RLock()
	defer shm.mu.RUnlock()
	
	if health, exists := shm.components[componentID]; exists {
		healthCopy := *health
		return &healthCopy
	}
	
	return nil
}

// GetAllComponentsHealth returns health status of all components
func (shm *SelfHealingMetrics) GetAllComponentsHealth() map[string]*ComponentHealth {
	shm.mu.RLock()
	defer shm.mu.RUnlock()
	
	result := make(map[string]*ComponentHealth)
	for id, health := range shm.components {
		healthCopy := *health
		result[id] = &healthCopy
	}
	
	return result
}

// IsSystemHealthy returns true if all components are in healthy state
func (shm *SelfHealingMetrics) IsSystemHealthy() bool {
	shm.mu.RLock()
	defer shm.mu.RUnlock()
	
	for _, health := range shm.components {
		if health.HealthStatus > 1 { // Unhealthy or critical
			return false
		}
	}
	
	return true
}

// GetUnhealthyComponents returns list of components that are not healthy
func (shm *SelfHealingMetrics) GetUnhealthyComponents() []string {
	shm.mu.RLock()
	defer shm.mu.RUnlock()
	
	var unhealthy []string
	for id, health := range shm.components {
		if health.HealthStatus > 0 { // Any status other than healthy
			unhealthy = append(unhealthy, id)
		}
	}
	
	return unhealthy
}