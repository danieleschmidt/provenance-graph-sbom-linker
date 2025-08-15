package concurrency

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// ResourcePool provides intelligent resource management with adaptive scaling
type ResourcePool struct {
	config              PoolConfig
	workers             []*Worker
	taskQueue           chan Task
	resultQueue         chan TaskResult
	workerManager       *WorkerManager
	loadBalancer        *LoadBalancer
	resourceMonitor     *ResourceMonitor
	adaptiveScaler      *AdaptiveScaler
	logger              *logger.StructuredLogger
	metricsCollector    *monitoring.MetricsCollector
	started             bool
	stopCh              chan bool
	mutex               sync.RWMutex
	stats               *PoolStats
}

type PoolConfig struct {
	MinWorkers          int
	MaxWorkers          int
	InitialWorkers      int
	TaskQueueSize       int
	ResultQueueSize     int
	WorkerTimeout       time.Duration
	ScalingInterval     time.Duration
	CPUThreshold        float64
	MemoryThreshold     float64
	QueueThreshold      float64
	AdaptiveScaling     bool
	LoadBalancing       bool
	ResourceMonitoring  bool
	HealthCheckInterval time.Duration
	GracefulShutdown    time.Duration
}

type Worker struct {
	id              int
	pool            *ResourcePool
	taskCh          chan Task
	stopCh          chan bool
	currentTask     *Task
	stats           *WorkerStats
	status          WorkerStatus
	lastActivity    time.Time
	resourceLimits  ResourceLimits
	mutex           sync.RWMutex
}

type WorkerStats struct {
	TasksProcessed    int64
	AverageExecTime   time.Duration
	ErrorCount        int64
	LastTaskTime      time.Time
	CPUUsage          float64
	MemoryUsageMB     float64
	SuccessRate       float64
}

type WorkerStatus int

const (
	WorkerStatusIdle WorkerStatus = iota
	WorkerStatusBusy
	WorkerStatusError
	WorkerStatusStopping
)

type Task struct {
	ID          string
	Type        string
	Priority    int
	Data        interface{}
	Executor    func(context.Context, interface{}) (interface{}, error)
	Timeout     time.Duration
	Retries     int
	CreatedAt   time.Time
	StartedAt   time.Time
	Context     context.Context
	Metadata    map[string]interface{}
}

type TaskResult struct {
	TaskID     string
	Result     interface{}
	Error      error
	Duration   time.Duration
	WorkerID   int
	Timestamp  time.Time
	Retries    int
}

type WorkerManager struct {
	pool           *ResourcePool
	healthChecker  *HealthChecker
	mutex          sync.RWMutex
}

type LoadBalancer struct {
	strategy       BalancingStrategy
	workerMetrics  map[int]*WorkerLoadMetrics
	mutex          sync.RWMutex
}

type BalancingStrategy int

const (
	RoundRobin BalancingStrategy = iota
	LeastConnections
	WeightedResponse
	ResourceBased
)

type WorkerLoadMetrics struct {
	ActiveTasks     int
	QueueLength     int
	ResponseTime    time.Duration
	CPUUsage        float64
	MemoryUsage     float64
	LastUpdate      time.Time
}

type ResourceMonitor struct {
	cpuUsage     float64
	memoryUsage  float64
	diskUsage    float64
	networkUsage float64
	lastUpdate   time.Time
	mutex        sync.RWMutex
}

type AdaptiveScaler struct {
	pool              *ResourcePool
	scalingHistory    []ScalingEvent
	predictiveModel   *ScalingModel
	mutex             sync.RWMutex
}

type ScalingEvent struct {
	Timestamp   time.Time
	Action      ScalingAction
	OldWorkers  int
	NewWorkers  int
	Reason      string
	CPULoad     float64
	MemoryLoad  float64
	QueueLoad   float64
}

type ScalingAction int

const (
	ScaleUp ScalingAction = iota
	ScaleDown
	NoAction
)

type ScalingModel struct {
	weightsLoadBased    map[string]float64
	weightsTimeBased    map[string]float64
	weightsHistorical   map[string]float64
	learningRate        float64
	confidence          float64
}

type ResourceLimits struct {
	MaxCPUPercent    float64
	MaxMemoryMB      float64
	MaxExecutionTime time.Duration
}

type PoolStats struct {
	TotalTasks        int64
	CompletedTasks    int64
	FailedTasks       int64
	ActiveWorkers     int32
	QueueSize         int32
	AverageExecTime   time.Duration
	ThroughputPerSec  float64
	ErrorRate         float64
	LastUpdate        time.Time
}

type HealthChecker struct {
	pool           *ResourcePool
	checkInterval  time.Duration
	healthHistory  map[int][]HealthCheck
	mutex          sync.RWMutex
}

type HealthCheck struct {
	Timestamp     time.Time
	IsHealthy     bool
	ResponseTime  time.Duration
	ErrorMessage  string
}

// NewResourcePool creates a new intelligent resource pool
func NewResourcePool(config PoolConfig, metricsCollector *monitoring.MetricsCollector) *ResourcePool {
	pool := &ResourcePool{
		config:           config,
		taskQueue:        make(chan Task, config.TaskQueueSize),
		resultQueue:      make(chan TaskResult, config.ResultQueueSize),
		logger:           logger.NewStructuredLogger("info", "json"),
		metricsCollector: metricsCollector,
		stopCh:           make(chan bool),
		stats:            &PoolStats{},
	}

	// Initialize components
	pool.workerManager = NewWorkerManager(pool)
	pool.loadBalancer = NewLoadBalancer(ResourceBased)
	pool.resourceMonitor = NewResourceMonitor()
	pool.adaptiveScaler = NewAdaptiveScaler(pool)

	return pool
}

// Start initializes and starts the resource pool
func (rp *ResourcePool) Start(ctx context.Context) error {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	if rp.started {
		return fmt.Errorf("resource pool already started")
	}

	// Create initial workers
	rp.workers = make([]*Worker, 0, rp.config.MaxWorkers)
	for i := 0; i < rp.config.InitialWorkers; i++ {
		worker := rp.createWorker(i)
		rp.workers = append(rp.workers, worker)
		go worker.Start(ctx)
	}

	// Start monitoring and scaling
	if rp.config.ResourceMonitoring {
		go rp.resourceMonitor.Start(ctx)
	}

	if rp.config.AdaptiveScaling {
		go rp.adaptiveScaler.Start(ctx)
	}

	// Start health checking
	go rp.workerManager.StartHealthChecking(ctx)

	// Start metrics collection
	go rp.metricsRoutine(ctx)

	// Start result processing
	go rp.processResults(ctx)

	rp.started = true
	atomic.StoreInt32(&rp.stats.ActiveWorkers, int32(len(rp.workers)))

	rp.logger.Info("resource_pool_started", map[string]interface{}{
		"initial_workers":     rp.config.InitialWorkers,
		"max_workers":         rp.config.MaxWorkers,
		"task_queue_size":     rp.config.TaskQueueSize,
		"adaptive_scaling":    rp.config.AdaptiveScaling,
		"load_balancing":      rp.config.LoadBalancing,
		"resource_monitoring": rp.config.ResourceMonitoring,
	})

	return nil
}

// SubmitTask submits a task to the resource pool
func (rp *ResourcePool) SubmitTask(task Task) error {
	if !rp.started {
		return fmt.Errorf("resource pool not started")
	}

	task.CreatedAt = time.Now()
	if task.ID == "" {
		task.ID = fmt.Sprintf("task_%d_%d", time.Now().UnixNano(), task.Priority)
	}

	select {
	case rp.taskQueue <- task:
		atomic.AddInt64(&rp.stats.TotalTasks, 1)
		atomic.AddInt32(&rp.stats.QueueSize, 1)
		rp.metricsCollector.RecordCounter("tasks_submitted_total", 1, map[string]string{"type": task.Type})
		return nil
	default:
		rp.metricsCollector.RecordCounter("tasks_rejected_total", 1, map[string]string{"reason": "queue_full"})
		return fmt.Errorf("task queue is full")
	}
}

// createWorker creates a new worker
func (rp *ResourcePool) createWorker(id int) *Worker {
	return &Worker{
		id:     id,
		pool:   rp,
		taskCh: make(chan Task, 1),
		stopCh: make(chan bool),
		stats:  &WorkerStats{},
		status: WorkerStatusIdle,
		resourceLimits: ResourceLimits{
			MaxCPUPercent:    80.0,
			MaxMemoryMB:      512.0,
			MaxExecutionTime: 5 * time.Minute,
		},
		lastActivity: time.Now(),
	}
}

// Start starts the worker
func (w *Worker) Start(ctx context.Context) {
	w.pool.logger.Info("worker_started", map[string]interface{}{"worker_id": w.id})

	for {
		select {
		case task := <-w.taskCh:
			w.processTask(ctx, task)
		case <-w.stopCh:
			w.pool.logger.Info("worker_stopped", map[string]interface{}{"worker_id": w.id})
			return
		case <-ctx.Done():
			return
		}
	}
}

// processTask processes a single task
func (w *Worker) processTask(ctx context.Context, task Task) {
	w.mutex.Lock()
	w.status = WorkerStatusBusy
	w.currentTask = &task
	w.lastActivity = time.Now()
	w.mutex.Unlock()

	startTime := time.Now()
	task.StartedAt = startTime

	// Create task context with timeout
	taskCtx := task.Context
	if taskCtx == nil {
		taskCtx = ctx
	}
	if task.Timeout > 0 {
		var cancel context.CancelFunc
		taskCtx, cancel = context.WithTimeout(taskCtx, task.Timeout)
		defer cancel()
	}

	// Execute task
	result, err := task.Executor(taskCtx, task.Data)
	duration := time.Since(startTime)

	// Update stats
	w.mutex.Lock()
	w.stats.TasksProcessed++
	w.stats.LastTaskTime = time.Now()
	if err != nil {
		w.stats.ErrorCount++
	}
	
	// Update average execution time
	if w.stats.AverageExecTime == 0 {
		w.stats.AverageExecTime = duration
	} else {
		w.stats.AverageExecTime = (w.stats.AverageExecTime + duration) / 2
	}
	
	w.stats.SuccessRate = float64(w.stats.TasksProcessed-w.stats.ErrorCount) / float64(w.stats.TasksProcessed)
	w.status = WorkerStatusIdle
	w.currentTask = nil
	w.mutex.Unlock()

	// Send result
	taskResult := TaskResult{
		TaskID:    task.ID,
		Result:    result,
		Error:     err,
		Duration:  duration,
		WorkerID:  w.id,
		Timestamp: time.Now(),
		Retries:   task.Retries,
	}

	select {
	case w.pool.resultQueue <- taskResult:
	default:
		w.pool.logger.Warn("result_queue_full", map[string]interface{}{"task_id": task.ID})
	}

	// Update pool stats
	atomic.AddInt64(&w.pool.stats.CompletedTasks, 1)
	atomic.AddInt32(&w.pool.stats.QueueSize, -1)
	if err != nil {
		atomic.AddInt64(&w.pool.stats.FailedTasks, 1)
	}
}

// processResults processes task results
func (rp *ResourcePool) processResults(ctx context.Context) {
	for {
		select {
		case result := <-rp.resultQueue:
			rp.handleTaskResult(result)
		case <-rp.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (rp *ResourcePool) handleTaskResult(result TaskResult) {
	// Record metrics
	labels := map[string]string{
		"worker_id": fmt.Sprintf("%d", result.WorkerID),
		"status":    "success",
	}
	if result.Error != nil {
		labels["status"] = "error"
	}

	rp.metricsCollector.RecordTiming("task_duration", result.Duration, labels)
	rp.metricsCollector.RecordCounter("tasks_completed_total", 1, labels)

	// Update load balancer metrics
	rp.loadBalancer.UpdateWorkerMetrics(result.WorkerID, result.Duration)

	// Log errors
	if result.Error != nil {
		rp.logger.Error("task_failed", map[string]interface{}{
			"task_id":   result.TaskID,
			"worker_id": result.WorkerID,
			"error":     result.Error.Error(),
			"duration":  result.Duration.String(),
		})
	}
}

// distributeTask distributes a task to the best available worker
func (rp *ResourcePool) distributeTask(ctx context.Context) {
	for {
		select {
		case task := <-rp.taskQueue:
			worker := rp.loadBalancer.SelectWorker(rp.workers)
			if worker != nil {
				select {
				case worker.taskCh <- task:
					// Task sent successfully
				default:
					// Worker queue full, try another worker or put back in main queue
					select {
					case rp.taskQueue <- task:
					default:
						rp.logger.Warn("task_dropped", map[string]interface{}{"task_id": task.ID})
					}
				}
			}
		case <-rp.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// GetStats returns comprehensive pool statistics
func (rp *ResourcePool) GetStats() *PoolStats {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	stats := *rp.stats
	stats.ActiveWorkers = int32(len(rp.workers))
	stats.QueueSize = int32(len(rp.taskQueue))
	stats.LastUpdate = time.Now()

	// Calculate throughput
	if stats.CompletedTasks > 0 && rp.started {
		// Simple throughput calculation
		stats.ThroughputPerSec = float64(stats.CompletedTasks) / time.Since(stats.LastUpdate).Seconds()
	}

	// Calculate error rate
	if stats.TotalTasks > 0 {
		stats.ErrorRate = float64(stats.FailedTasks) / float64(stats.TotalTasks)
	}

	return &stats
}

// GetWorkerStats returns detailed worker statistics
func (rp *ResourcePool) GetWorkerStats() map[int]*WorkerStats {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	stats := make(map[int]*WorkerStats)
	for _, worker := range rp.workers {
		worker.mutex.RLock()
		workerStats := *worker.stats
		worker.mutex.RUnlock()
		stats[worker.id] = &workerStats
	}

	return stats
}

// metricsRoutine collects and reports metrics
func (rp *ResourcePool) metricsRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rp.recordMetrics()
		case <-rp.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (rp *ResourcePool) recordMetrics() {
	stats := rp.GetStats()
	
	rp.metricsCollector.RecordGauge("pool_active_workers", float64(stats.ActiveWorkers), nil)
	rp.metricsCollector.RecordGauge("pool_queue_size", float64(stats.QueueSize), nil)
	rp.metricsCollector.RecordGauge("pool_throughput_per_sec", stats.ThroughputPerSec, nil)
	rp.metricsCollector.RecordGauge("pool_error_rate", stats.ErrorRate, nil)
	rp.metricsCollector.RecordCounter("pool_total_tasks", stats.TotalTasks, nil)
	rp.metricsCollector.RecordCounter("pool_completed_tasks", stats.CompletedTasks, nil)
	rp.metricsCollector.RecordCounter("pool_failed_tasks", stats.FailedTasks, nil)

	// Record system resource usage
	if rp.config.ResourceMonitoring {
		resources := rp.resourceMonitor.GetCurrentUsage()
		rp.metricsCollector.RecordGauge("system_cpu_usage", resources.CPUUsage, nil)
		rp.metricsCollector.RecordGauge("system_memory_usage", resources.MemoryUsage, nil)
	}
}

// Helper constructors and implementations

func NewWorkerManager(pool *ResourcePool) *WorkerManager {
	return &WorkerManager{
		pool:          pool,
		healthChecker: &HealthChecker{
			pool:          pool,
			checkInterval: pool.config.HealthCheckInterval,
			healthHistory: make(map[int][]HealthCheck),
		},
	}
}

func (wm *WorkerManager) StartHealthChecking(ctx context.Context) {
	ticker := time.NewTicker(wm.pool.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wm.performHealthChecks()
		case <-wm.pool.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (wm *WorkerManager) performHealthChecks() {
	for _, worker := range wm.pool.workers {
		isHealthy := wm.checkWorkerHealth(worker)
		
		healthCheck := HealthCheck{
			Timestamp: time.Now(),
			IsHealthy: isHealthy,
		}

		wm.healthChecker.mutex.Lock()
		if wm.healthChecker.healthHistory[worker.id] == nil {
			wm.healthChecker.healthHistory[worker.id] = make([]HealthCheck, 0, 100)
		}
		wm.healthChecker.healthHistory[worker.id] = append(wm.healthChecker.healthHistory[worker.id], healthCheck)
		
		// Keep only last 100 checks
		if len(wm.healthChecker.healthHistory[worker.id]) > 100 {
			wm.healthChecker.healthHistory[worker.id] = wm.healthChecker.healthHistory[worker.id][1:]
		}
		wm.healthChecker.mutex.Unlock()

		if !isHealthy {
			wm.handleUnhealthyWorker(worker)
		}
	}
}

func (wm *WorkerManager) checkWorkerHealth(worker *Worker) bool {
	worker.mutex.RLock()
	defer worker.mutex.RUnlock()

	// Check if worker is stuck
	if worker.status == WorkerStatusBusy && time.Since(worker.lastActivity) > wm.pool.config.WorkerTimeout {
		return false
	}

	// Check error rate
	if worker.stats.TasksProcessed > 10 && worker.stats.SuccessRate < 0.5 {
		return false
	}

	return true
}

func (wm *WorkerManager) handleUnhealthyWorker(worker *Worker) {
	wm.pool.logger.Warn("unhealthy_worker_detected", map[string]interface{}{
		"worker_id": worker.id,
		"status":    worker.status,
		"last_activity": worker.lastActivity,
	})

	// For now, just log - in production, might restart the worker
}

func NewLoadBalancer(strategy BalancingStrategy) *LoadBalancer {
	return &LoadBalancer{
		strategy:      strategy,
		workerMetrics: make(map[int]*WorkerLoadMetrics),
	}
}

func (lb *LoadBalancer) SelectWorker(workers []*Worker) *Worker {
	if len(workers) == 0 {
		return nil
	}

	switch lb.strategy {
	case ResourceBased:
		return lb.selectByResourceUsage(workers)
	case LeastConnections:
		return lb.selectByLeastConnections(workers)
	default:
		return lb.selectRoundRobin(workers)
	}
}

func (lb *LoadBalancer) selectByResourceUsage(workers []*Worker) *Worker {
	var bestWorker *Worker
	var bestScore float64 = -1

	for _, worker := range workers {
		if worker.status != WorkerStatusIdle {
			continue
		}

		// Calculate composite score based on resource usage
		worker.mutex.RLock()
		cpuScore := 1.0 - (worker.stats.CPUUsage / 100.0)
		memoryScore := 1.0 - (worker.stats.MemoryUsageMB / worker.resourceLimits.MaxMemoryMB)
		responseScore := 1.0 / (1.0 + worker.stats.AverageExecTime.Seconds())
		worker.mutex.RUnlock()

		score := (cpuScore + memoryScore + responseScore) / 3.0

		if bestWorker == nil || score > bestScore {
			bestWorker = worker
			bestScore = score
		}
	}

	return bestWorker
}

func (lb *LoadBalancer) selectByLeastConnections(workers []*Worker) *Worker {
	var bestWorker *Worker
	var minConnections int = int(^uint(0) >> 1) // Max int

	for _, worker := range workers {
		if worker.status != WorkerStatusIdle {
			continue
		}

		connections := len(worker.taskCh)
		if connections < minConnections {
			bestWorker = worker
			minConnections = connections
		}
	}

	return bestWorker
}

func (lb *LoadBalancer) selectRoundRobin(workers []*Worker) *Worker {
	for _, worker := range workers {
		if worker.status == WorkerStatusIdle {
			return worker
		}
	}
	return nil
}

func (lb *LoadBalancer) UpdateWorkerMetrics(workerID int, responseTime time.Duration) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	metrics, exists := lb.workerMetrics[workerID]
	if !exists {
		metrics = &WorkerLoadMetrics{}
		lb.workerMetrics[workerID] = metrics
	}

	metrics.ResponseTime = responseTime
	metrics.LastUpdate = time.Now()
}

func NewResourceMonitor() *ResourceMonitor {
	return &ResourceMonitor{}
}

func (rm *ResourceMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.updateResourceUsage()
		case <-ctx.Done():
			return
		}
	}
}

func (rm *ResourceMonitor) updateResourceUsage() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Get runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	rm.memoryUsage = float64(memStats.Alloc) / 1024 / 1024 // MB
	rm.lastUpdate = time.Now()

	// For CPU usage, in production you'd use a proper system monitoring library
	rm.cpuUsage = float64(runtime.NumGoroutine()) / 1000.0 * 100.0 // Simplified
}

type ResourceUsage struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	NetworkUsage float64
}

func (rm *ResourceMonitor) GetCurrentUsage() ResourceUsage {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return ResourceUsage{
		CPUUsage:    rm.cpuUsage,
		MemoryUsage: rm.memoryUsage,
		DiskUsage:   rm.diskUsage,
		NetworkUsage: rm.networkUsage,
	}
}

func NewAdaptiveScaler(pool *ResourcePool) *AdaptiveScaler {
	return &AdaptiveScaler{
		pool:            pool,
		scalingHistory:  make([]ScalingEvent, 0, 1000),
		predictiveModel: &ScalingModel{
			weightsLoadBased:  map[string]float64{"cpu": 0.3, "memory": 0.3, "queue": 0.4},
			weightsTimeBased:  map[string]float64{"hour": 0.5, "day": 0.3, "week": 0.2},
			weightsHistorical: map[string]float64{"recent": 0.6, "trend": 0.4},
			learningRate:      0.01,
			confidence:        0.5,
		},
	}
}

func (as *AdaptiveScaler) Start(ctx context.Context) {
	ticker := time.NewTicker(as.pool.config.ScalingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			as.evaluateScaling()
		case <-as.pool.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (as *AdaptiveScaler) evaluateScaling() {
	currentWorkers := len(as.pool.workers)
	resourceUsage := as.pool.resourceMonitor.GetCurrentUsage()
	queueLoad := float64(len(as.pool.taskQueue)) / float64(cap(as.pool.taskQueue))

	action := as.determineScalingAction(resourceUsage, queueLoad)
	
	switch action {
	case ScaleUp:
		if currentWorkers < as.pool.config.MaxWorkers {
			as.scaleUp("high_load")
		}
	case ScaleDown:
		if currentWorkers > as.pool.config.MinWorkers {
			as.scaleDown("low_load")
		}
	}
}

func (as *AdaptiveScaler) determineScalingAction(resources ResourceUsage, queueLoad float64) ScalingAction {
	// Simple rule-based scaling for Generation 3
	if resources.CPUUsage > as.pool.config.CPUThreshold || 
	   resources.MemoryUsage > as.pool.config.MemoryThreshold || 
	   queueLoad > as.pool.config.QueueThreshold {
		return ScaleUp
	}

	if resources.CPUUsage < as.pool.config.CPUThreshold*0.5 && 
	   resources.MemoryUsage < as.pool.config.MemoryThreshold*0.5 && 
	   queueLoad < as.pool.config.QueueThreshold*0.3 {
		return ScaleDown
	}

	return NoAction
}

func (as *AdaptiveScaler) scaleUp(reason string) {
	as.pool.mutex.Lock()
	defer as.pool.mutex.Unlock()

	oldWorkers := len(as.pool.workers)
	workerID := len(as.pool.workers)
	
	worker := as.pool.createWorker(workerID)
	as.pool.workers = append(as.pool.workers, worker)
	go worker.Start(context.Background())

	event := ScalingEvent{
		Timestamp:  time.Now(),
		Action:     ScaleUp,
		OldWorkers: oldWorkers,
		NewWorkers: len(as.pool.workers),
		Reason:     reason,
	}

	as.mutex.Lock()
	as.scalingHistory = append(as.scalingHistory, event)
	if len(as.scalingHistory) > 1000 {
		as.scalingHistory = as.scalingHistory[1:]
	}
	as.mutex.Unlock()

	atomic.StoreInt32(&as.pool.stats.ActiveWorkers, int32(len(as.pool.workers)))

	as.pool.logger.Info("scaled_up", map[string]interface{}{
		"old_workers": oldWorkers,
		"new_workers": len(as.pool.workers),
		"reason":      reason,
	})
}

func (as *AdaptiveScaler) scaleDown(reason string) {
	as.pool.mutex.Lock()
	defer as.pool.mutex.Unlock()

	if len(as.pool.workers) <= as.pool.config.MinWorkers {
		return
	}

	oldWorkers := len(as.pool.workers)
	
	// Remove the last worker
	lastWorker := as.pool.workers[len(as.pool.workers)-1]
	close(lastWorker.stopCh)
	as.pool.workers = as.pool.workers[:len(as.pool.workers)-1]

	event := ScalingEvent{
		Timestamp:  time.Now(),
		Action:     ScaleDown,
		OldWorkers: oldWorkers,
		NewWorkers: len(as.pool.workers),
		Reason:     reason,
	}

	as.mutex.Lock()
	as.scalingHistory = append(as.scalingHistory, event)
	if len(as.scalingHistory) > 1000 {
		as.scalingHistory = as.scalingHistory[1:]
	}
	as.mutex.Unlock()

	atomic.StoreInt32(&as.pool.stats.ActiveWorkers, int32(len(as.pool.workers)))

	as.pool.logger.Info("scaled_down", map[string]interface{}{
		"old_workers": oldWorkers,
		"new_workers": len(as.pool.workers),
		"reason":      reason,
	})
}

// Stop gracefully shuts down the resource pool
func (rp *ResourcePool) Stop(ctx context.Context) error {
	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	if !rp.started {
		return nil
	}

	// Stop accepting new tasks
	close(rp.stopCh)

	// Wait for workers to finish or timeout
	stopCtx, cancel := context.WithTimeout(ctx, rp.config.GracefulShutdown)
	defer cancel()

	var wg sync.WaitGroup
	for _, worker := range rp.workers {
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()
			close(w.stopCh)
		}(worker)
	}

	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		rp.logger.Info("resource_pool_stopped_gracefully", nil)
	case <-stopCtx.Done():
		rp.logger.Warn("resource_pool_stopped_with_timeout", nil)
	}

	rp.started = false
	return nil
}