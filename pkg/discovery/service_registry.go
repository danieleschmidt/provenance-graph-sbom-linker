package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// ServiceRegistry manages service discovery and registration
type ServiceRegistry interface {
	RegisterService(service *Service) error
	DeregisterService(serviceID string) error
	DiscoverServices(serviceName string) ([]*Service, error)
	GetService(serviceID string) (*Service, error)
	ListServices() ([]*Service, error)
	WatchServices(serviceName string) (<-chan ServiceEvent, error)
	Start(ctx context.Context) error
	Stop() error
}

// Service represents a registered service
type Service struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	Health      ServiceHealth     `json:"health"`
	Metadata    map[string]string `json:"metadata"`
	Tags        []string          `json:"tags"`
	RegisteredAt time.Time        `json:"registered_at"`
	LastSeen    time.Time         `json:"last_seen"`
	TTL         time.Duration     `json:"ttl"`
}

// ServiceHealth represents service health status
type ServiceHealth struct {
	Status      HealthStatus `json:"status"`
	LastCheck   time.Time    `json:"last_check"`
	Message     string       `json:"message,omitempty"`
	CheckCount  int64        `json:"check_count"`
	FailCount   int64        `json:"fail_count"`
}

// HealthStatus represents the health status of a service
type HealthStatus string

const (
	HealthStatusUnknown  HealthStatus = "unknown"
	HealthStatusHealthy  HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusCritical HealthStatus = "critical"
)

// ServiceEvent represents a service registry event
type ServiceEvent struct {
	Type      EventType `json:"type"`
	Service   *Service  `json:"service"`
	Timestamp time.Time `json:"timestamp"`
}

// EventType represents the type of service event
type EventType string

const (
	EventTypeRegistered   EventType = "registered"
	EventTypeDeregistered EventType = "deregistered"
	EventTypeHealthChanged EventType = "health_changed"
	EventTypeUpdated      EventType = "updated"
)

// InMemoryServiceRegistry provides an in-memory service registry
type InMemoryServiceRegistry struct {
	services       map[string]*Service
	servicesByName map[string][]*Service
	watchers       map[string][]chan ServiceEvent
	mutex          sync.RWMutex
	logger         *logger.StructuredLogger
	metrics        *monitoring.MetricsCollector
	config         *RegistryConfig
	running        bool
	stopCh         chan bool
	healthChecker  *ServiceHealthChecker
}

// RegistryConfig contains service registry configuration
type RegistryConfig struct {
	DefaultTTL          time.Duration `json:"default_ttl"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`
	MaxRetries          int           `json:"max_retries"`
}

// ServiceHealthChecker manages health checking for registered services
type ServiceHealthChecker struct {
	registry *InMemoryServiceRegistry
	config   *RegistryConfig
	logger   *logger.StructuredLogger
	metrics  *monitoring.MetricsCollector
}

// NewInMemoryServiceRegistry creates a new in-memory service registry
func NewInMemoryServiceRegistry(config *RegistryConfig, metrics *monitoring.MetricsCollector) *InMemoryServiceRegistry {
	if config == nil {
		config = &RegistryConfig{
			DefaultTTL:          5 * time.Minute,
			HealthCheckInterval: 30 * time.Second,
			CleanupInterval:     time.Minute,
			HealthCheckTimeout:  5 * time.Second,
			MaxRetries:          3,
		}
	}

	registry := &InMemoryServiceRegistry{
		services:       make(map[string]*Service),
		servicesByName: make(map[string][]*Service),
		watchers:       make(map[string][]chan ServiceEvent),
		logger:         logger.NewStructuredLogger("info", "json"),
		metrics:        metrics,
		config:         config,
		stopCh:         make(chan bool),
	}

	registry.healthChecker = &ServiceHealthChecker{
		registry: registry,
		config:   config,
		logger:   logger.NewStructuredLogger("info", "json"),
		metrics:  metrics,
	}

	return registry
}

// RegisterService registers a new service
func (r *InMemoryServiceRegistry) RegisterService(service *Service) error {
	if service == nil {
		return fmt.Errorf("service cannot be nil")
	}

	if service.ID == "" {
		return fmt.Errorf("service ID is required")
	}

	if service.Name == "" {
		return fmt.Errorf("service name is required")
	}

	// Set defaults
	if service.TTL == 0 {
		service.TTL = r.config.DefaultTTL
	}

	if service.Metadata == nil {
		service.Metadata = make(map[string]string)
	}

	if service.Tags == nil {
		service.Tags = make([]string, 0)
	}

	now := time.Now()
	service.RegisteredAt = now
	service.LastSeen = now
	service.Health.Status = HealthStatusUnknown
	service.Health.LastCheck = now

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if service already exists
	if existing, exists := r.services[service.ID]; exists {
		// Update existing service
		existing.Version = service.Version
		existing.Address = service.Address
		existing.Port = service.Port
		existing.Protocol = service.Protocol
		existing.Metadata = service.Metadata
		existing.Tags = service.Tags
		existing.TTL = service.TTL
		existing.LastSeen = now

		r.logger.Info("service_updated", map[string]interface{}{
			"service_id":   service.ID,
			"service_name": service.Name,
			"address":      service.Address,
			"port":         service.Port,
		})

		r.notifyWatchers(service.Name, ServiceEvent{
			Type:      EventTypeUpdated,
			Service:   existing,
			Timestamp: now,
		})

		return nil
	}

	// Register new service
	r.services[service.ID] = service

	// Add to services by name index
	if r.servicesByName[service.Name] == nil {
		r.servicesByName[service.Name] = make([]*Service, 0)
	}
	r.servicesByName[service.Name] = append(r.servicesByName[service.Name], service)

	// Record metrics
	if r.metrics != nil {
		r.metrics.RecordGauge("services_registered", float64(len(r.services)), nil)
		r.metrics.RecordCounter("service_registrations_total", 1, map[string]string{
			"service_name": service.Name,
		})
	}

	r.logger.Info("service_registered", map[string]interface{}{
		"service_id":   service.ID,
		"service_name": service.Name,
		"address":      service.Address,
		"port":         service.Port,
		"ttl":          service.TTL.String(),
	})

	// Notify watchers
	r.notifyWatchers(service.Name, ServiceEvent{
		Type:      EventTypeRegistered,
		Service:   service,
		Timestamp: now,
	})

	return nil
}

// DeregisterService removes a service from the registry
func (r *InMemoryServiceRegistry) DeregisterService(serviceID string) error {
	if serviceID == "" {
		return fmt.Errorf("service ID is required")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	service, exists := r.services[serviceID]
	if !exists {
		return fmt.Errorf("service not found: %s", serviceID)
	}

	// Remove from main index
	delete(r.services, serviceID)

	// Remove from name index
	if services, exists := r.servicesByName[service.Name]; exists {
		for i, s := range services {
			if s.ID == serviceID {
				r.servicesByName[service.Name] = append(services[:i], services[i+1:]...)
				break
			}
		}

		// Remove empty slice
		if len(r.servicesByName[service.Name]) == 0 {
			delete(r.servicesByName, service.Name)
		}
	}

	// Record metrics
	if r.metrics != nil {
		r.metrics.RecordGauge("services_registered", float64(len(r.services)), nil)
		r.metrics.RecordCounter("service_deregistrations_total", 1, map[string]string{
			"service_name": service.Name,
		})
	}

	r.logger.Info("service_deregistered", map[string]interface{}{
		"service_id":   serviceID,
		"service_name": service.Name,
	})

	// Notify watchers
	r.notifyWatchers(service.Name, ServiceEvent{
		Type:      EventTypeDeregistered,
		Service:   service,
		Timestamp: time.Now(),
	})

	return nil
}

// DiscoverServices returns all healthy services with the given name
func (r *InMemoryServiceRegistry) DiscoverServices(serviceName string) ([]*Service, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("service name is required")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	services, exists := r.servicesByName[serviceName]
	if !exists {
		return []*Service{}, nil
	}

	// Filter healthy services
	healthyServices := make([]*Service, 0)
	for _, service := range services {
		if r.isServiceAlive(service) && service.Health.Status == HealthStatusHealthy {
			healthyServices = append(healthyServices, service)
		}
	}

	r.logger.Debug("services_discovered", map[string]interface{}{
		"service_name":    serviceName,
		"total_services":  len(services),
		"healthy_services": len(healthyServices),
	})

	return healthyServices, nil
}

// GetService returns a specific service by ID
func (r *InMemoryServiceRegistry) GetService(serviceID string) (*Service, error) {
	if serviceID == "" {
		return nil, fmt.Errorf("service ID is required")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	service, exists := r.services[serviceID]
	if !exists {
		return nil, fmt.Errorf("service not found: %s", serviceID)
	}

	return service, nil
}

// ListServices returns all registered services
func (r *InMemoryServiceRegistry) ListServices() ([]*Service, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	services := make([]*Service, 0, len(r.services))
	for _, service := range r.services {
		services = append(services, service)
	}

	return services, nil
}

// WatchServices returns a channel for service events
func (r *InMemoryServiceRegistry) WatchServices(serviceName string) (<-chan ServiceEvent, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("service name is required")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	eventCh := make(chan ServiceEvent, 100)

	if r.watchers[serviceName] == nil {
		r.watchers[serviceName] = make([]chan ServiceEvent, 0)
	}
	r.watchers[serviceName] = append(r.watchers[serviceName], eventCh)

	r.logger.Info("watcher_added", map[string]interface{}{
		"service_name": serviceName,
		"watchers":     len(r.watchers[serviceName]),
	})

	return eventCh, nil
}

// Start starts the service registry
func (r *InMemoryServiceRegistry) Start(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.running {
		return fmt.Errorf("service registry already running")
	}

	r.running = true

	// Start background tasks
	go r.healthCheckLoop(ctx)
	go r.cleanupLoop(ctx)

	r.logger.Info("service_registry_started", map[string]interface{}{
		"config": r.config,
	})

	return nil
}

// Stop stops the service registry
func (r *InMemoryServiceRegistry) Stop() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.running {
		return nil
	}

	r.running = false
	close(r.stopCh)

	// Close all watcher channels
	for _, watchers := range r.watchers {
		for _, ch := range watchers {
			close(ch)
		}
	}
	r.watchers = make(map[string][]chan ServiceEvent)

	r.logger.Info("service_registry_stopped", map[string]interface{}{
		"registered_services": len(r.services),
	})

	return nil
}

// healthCheckLoop runs health checks periodically
func (r *InMemoryServiceRegistry) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(r.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.healthChecker.checkAllServices()
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// cleanupLoop removes expired services
func (r *InMemoryServiceRegistry) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(r.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupExpiredServices()
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// cleanupExpiredServices removes services that have exceeded their TTL
func (r *InMemoryServiceRegistry) cleanupExpiredServices() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	expiredServices := make([]*Service, 0)

	for _, service := range r.services {
		if !r.isServiceAlive(service) {
			expiredServices = append(expiredServices, service)
		}
	}

	for _, service := range expiredServices {
		delete(r.services, service.ID)

		// Remove from name index
		if services, exists := r.servicesByName[service.Name]; exists {
			for i, s := range services {
				if s.ID == service.ID {
					r.servicesByName[service.Name] = append(services[:i], services[i+1:]...)
					break
				}
			}

			// Remove empty slice
			if len(r.servicesByName[service.Name]) == 0 {
				delete(r.servicesByName, service.Name)
			}
		}

		r.logger.Info("service_expired", map[string]interface{}{
			"service_id":   service.ID,
			"service_name": service.Name,
			"last_seen":    service.LastSeen.Format(time.RFC3339),
		})

		// Notify watchers
		r.notifyWatchers(service.Name, ServiceEvent{
			Type:      EventTypeDeregistered,
			Service:   service,
			Timestamp: now,
		})
	}

	if len(expiredServices) > 0 && r.metrics != nil {
		r.metrics.RecordGauge("services_registered", float64(len(r.services)), nil)
		r.metrics.RecordCounter("services_expired_total", int64(len(expiredServices)), nil)
	}
}

// isServiceAlive checks if a service is still alive based on TTL
func (r *InMemoryServiceRegistry) isServiceAlive(service *Service) bool {
	return time.Since(service.LastSeen) < service.TTL
}

// notifyWatchers sends events to all watchers of a service
func (r *InMemoryServiceRegistry) notifyWatchers(serviceName string, event ServiceEvent) {
	watchers, exists := r.watchers[serviceName]
	if !exists {
		return
	}

	for _, ch := range watchers {
		select {
		case ch <- event:
		default:
			// Channel is full, skip
		}
	}
}

// checkAllServices performs health checks on all services
func (hc *ServiceHealthChecker) checkAllServices() {
	hc.registry.mutex.RLock()
	services := make([]*Service, 0, len(hc.registry.services))
	for _, service := range hc.registry.services {
		services = append(services, service)
	}
	hc.registry.mutex.RUnlock()

	for _, service := range services {
		go hc.checkService(service)
	}
}

// checkService performs a health check on a single service
func (hc *ServiceHealthChecker) checkService(service *Service) {
	if !hc.registry.isServiceAlive(service) {
		return
	}

	startTime := time.Now()

	// Perform health check (simplified - in real implementation, use HTTP client)
	var healthy bool
	var message string

	// Mock health check - in real implementation, make HTTP request
	if service.Health.FailCount < int64(hc.config.MaxRetries) {
		healthy = true
		message = "Service is healthy"
	} else {
		healthy = false
		message = "Service failed health check"
	}

	// Update service health
	var status HealthStatus
	if healthy {
		status = HealthStatusHealthy
		service.Health.FailCount = 0
	} else {
		status = HealthStatusUnhealthy
		service.Health.FailCount++
	}

	hc.updateServiceHealth(service, status, message)

	// Record metrics
	if hc.metrics != nil {
		duration := time.Since(startTime)
		hc.metrics.RecordTiming("service_health_check_duration_ms", duration, map[string]string{
			"service_name": service.Name,
			"service_id":   service.ID,
			"healthy":      fmt.Sprintf("%t", healthy),
		})
	}
}

// updateServiceHealth updates the health status of a service
func (hc *ServiceHealthChecker) updateServiceHealth(service *Service, status HealthStatus, message string) {
	oldStatus := service.Health.Status

	service.Health.Status = status
	service.Health.LastCheck = time.Now()
	service.Health.Message = message
	service.Health.CheckCount++

	// Notify watchers if status changed
	if oldStatus != status {
		hc.registry.mutex.RLock()
		hc.registry.notifyWatchers(service.Name, ServiceEvent{
			Type:      EventTypeHealthChanged,
			Service:   service,
			Timestamp: time.Now(),
		})
		hc.registry.mutex.RUnlock()

		hc.logger.Info("service_health_changed", map[string]interface{}{
			"service_id":   service.ID,
			"service_name": service.Name,
			"old_status":   string(oldStatus),
			"new_status":   string(status),
			"message":      message,
		})
	}
}

// GetURL returns the full URL for a service
func (s *Service) GetURL() string {
	return fmt.Sprintf("%s://%s:%d", s.Protocol, s.Address, s.Port)
}

// IsHealthy returns true if the service is healthy
func (s *Service) IsHealthy() bool {
	return s.Health.Status == HealthStatusHealthy
}

// ToJSON returns the service as JSON
func (s *Service) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}