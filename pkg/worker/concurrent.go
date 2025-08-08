package worker

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Job represents a unit of work
type Job interface {
	ID() string
	Execute(ctx context.Context) error
	Priority() int
	Deadline() time.Time
	Retry() bool
	MaxRetries() int
}

// Result represents the result of job execution
type Result struct {
	JobID      string        `json:"job_id"`
	Success    bool          `json:"success"`
	Error      error         `json:"error,omitempty"`
	Duration   time.Duration `json:"duration"`
	StartTime  time.Time     `json:"start_time"`
	FinishTime time.Time     `json:"finish_time"`
	Attempts   int           `json:"attempts"`
}

// WorkerPool manages a pool of workers for concurrent job processing
type WorkerPool struct {
	workers    int
	jobQueue   chan Job
	resultChan chan Result
	quit       chan bool
	wg         sync.WaitGroup
	
	// Metrics
	processed     int64
	failed        int64
	active        int64
	queueSize     int64
	maxQueueSizeMetric  int64
	
	// Configuration
	retryDelay    time.Duration
	maxQueueSize  int
	healthChecker HealthChecker
	
	// State
	running bool
	mutex   sync.RWMutex
}

// HealthChecker defines interface for worker health monitoring
type HealthChecker interface {
	IsHealthy(workerID int) bool
	RecordMetrics(workerID int, duration time.Duration, success bool)
}

// DefaultHealthChecker provides basic health checking
type DefaultHealthChecker struct {
	workerMetrics map[int]*WorkerMetrics
	mutex         sync.RWMutex
}

type WorkerMetrics struct {
	TasksProcessed int64         `json:"tasks_processed"`
	TasksFailed    int64         `json:"tasks_failed"`
	AvgDuration    time.Duration `json:"avg_duration"`
	LastSeen       time.Time     `json:"last_seen"`
	IsHealthy      bool          `json:"is_healthy"`
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	
	if queueSize <= 0 {
		queueSize = workers * 100
	}

	return &WorkerPool{
		workers:       workers,
		jobQueue:      make(chan Job, queueSize),
		resultChan:    make(chan Result, queueSize),
		quit:          make(chan bool),
		maxQueueSizeMetric:  int64(queueSize),
		retryDelay:    time.Second * 5,
		healthChecker: NewDefaultHealthChecker(),
	}
}

// NewDefaultHealthChecker creates a default health checker
func NewDefaultHealthChecker() *DefaultHealthChecker {
	return &DefaultHealthChecker{
		workerMetrics: make(map[int]*WorkerMetrics),
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start(ctx context.Context) error {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	
	if wp.running {
		return fmt.Errorf("worker pool is already running")
	}

	wp.running = true
	
	// Start workers
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}

	// Start result processor
	go wp.processResults(ctx)

	return nil
}

// Stop gracefully stops the worker pool
func (wp *WorkerPool) Stop(ctx context.Context) error {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()
	
	if !wp.running {
		return nil
	}

	wp.running = false
	close(wp.quit)
	
	// Wait for workers to finish with timeout
	done := make(chan bool)
	go func() {
		wp.wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		close(wp.jobQueue)
		close(wp.resultChan)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Submit adds a job to the queue
func (wp *WorkerPool) Submit(job Job) error {
	wp.mutex.RLock()
	running := wp.running
	wp.mutex.RUnlock()
	
	if !running {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case wp.jobQueue <- job:
		atomic.AddInt64(&wp.queueSize, 1)
		return nil
	default:
		return fmt.Errorf("job queue is full")
	}
}

// SubmitBatch submits multiple jobs
func (wp *WorkerPool) SubmitBatch(jobs []Job) error {
	for _, job := range jobs {
		if err := wp.Submit(job); err != nil {
			return fmt.Errorf("failed to submit job %s: %w", job.ID(), err)
		}
	}
	return nil
}

// Results returns the result channel
func (wp *WorkerPool) Results() <-chan Result {
	return wp.resultChan
}

// GetMetrics returns worker pool metrics
func (wp *WorkerPool) GetMetrics() *PoolMetrics {
	return &PoolMetrics{
		ActiveWorkers:   int(atomic.LoadInt64(&wp.active)),
		TotalWorkers:    wp.workers,
		QueueSize:       int(atomic.LoadInt64(&wp.queueSize)),
		MaxQueueSize:    int(wp.maxQueueSize),
		TasksProcessed:  atomic.LoadInt64(&wp.processed),
		TasksFailed:     atomic.LoadInt64(&wp.failed),
		IsRunning:       wp.isRunning(),
	}
}

// worker is the main worker goroutine
func (wp *WorkerPool) worker(ctx context.Context, workerID int) {
	defer wp.wg.Done()

	for {
		select {
		case job := <-wp.jobQueue:
			if job == nil {
				return
			}
			
			atomic.AddInt64(&wp.active, 1)
			atomic.AddInt64(&wp.queueSize, -1)
			
			result := wp.executeJob(ctx, job, workerID)
			
			select {
			case wp.resultChan <- result:
			case <-ctx.Done():
				atomic.AddInt64(&wp.active, -1)
				return
			}
			
			atomic.AddInt64(&wp.active, -1)
			
		case <-wp.quit:
			return
		case <-ctx.Done():
			return
		}
	}
}

// executeJob executes a single job with retry logic
func (wp *WorkerPool) executeJob(ctx context.Context, job Job, workerID int) Result {
	startTime := time.Now()
	var lastErr error
	
	maxRetries := job.MaxRetries()
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Check deadline
		if !job.Deadline().IsZero() && time.Now().After(job.Deadline()) {
			lastErr = fmt.Errorf("job deadline exceeded")
			break
		}

		// Check worker health
		if !wp.healthChecker.IsHealthy(workerID) {
			lastErr = fmt.Errorf("worker %d is unhealthy", workerID)
			break
		}

		execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := job.Execute(execCtx)
		cancel()

		if err == nil {
			// Success
			duration := time.Since(startTime)
			atomic.AddInt64(&wp.processed, 1)
			wp.healthChecker.RecordMetrics(workerID, duration, true)
			
			return Result{
				JobID:      job.ID(),
				Success:    true,
				Duration:   duration,
				StartTime:  startTime,
				FinishTime: time.Now(),
				Attempts:   attempt,
			}
		}

		lastErr = err
		wp.healthChecker.RecordMetrics(workerID, time.Since(startTime), false)

		// Check if job should be retried
		if !job.Retry() || attempt >= maxRetries {
			break
		}

		// Wait before retry with exponential backoff
		retryDelay := wp.retryDelay * time.Duration(attempt)
		if retryDelay > time.Minute {
			retryDelay = time.Minute
		}

		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			lastErr = ctx.Err()
			break
		}
	}

	// Job failed
	atomic.AddInt64(&wp.failed, 1)
	
	return Result{
		JobID:      job.ID(),
		Success:    false,
		Error:      lastErr,
		Duration:   time.Since(startTime),
		StartTime:  startTime,
		FinishTime: time.Now(),
		Attempts:   maxRetries,
	}
}

// processResults processes job results
func (wp *WorkerPool) processResults(ctx context.Context) {
	for {
		select {
		case result := <-wp.resultChan:
			// Process result (logging, metrics, etc.)
			if result.Error != nil {
				// Log error or send to error handling system
			}
		case <-ctx.Done():
			return
		}
	}
}

// isRunning safely checks if the pool is running
func (wp *WorkerPool) isRunning() bool {
	wp.mutex.RLock()
	defer wp.mutex.RUnlock()
	return wp.running
}

// PoolMetrics contains worker pool performance metrics
type PoolMetrics struct {
	ActiveWorkers   int   `json:"active_workers"`
	TotalWorkers    int   `json:"total_workers"`
	QueueSize       int   `json:"queue_size"`
	MaxQueueSize    int   `json:"max_queue_size"`
	TasksProcessed  int64 `json:"tasks_processed"`
	TasksFailed     int64 `json:"tasks_failed"`
	IsRunning       bool  `json:"is_running"`
}

// Throughput calculates tasks per second
func (pm *PoolMetrics) Throughput() float64 {
	total := pm.TasksProcessed + pm.TasksFailed
	if total == 0 {
		return 0
	}
	// This would need actual time tracking in production
	return float64(total) / 60.0 // Placeholder: tasks per minute
}

// SuccessRate calculates the success rate
func (pm *PoolMetrics) SuccessRate() float64 {
	total := pm.TasksProcessed + pm.TasksFailed
	if total == 0 {
		return 0
	}
	return float64(pm.TasksProcessed) / float64(total)
}

// QueueUtilization calculates queue utilization percentage
func (pm *PoolMetrics) QueueUtilization() float64 {
	if pm.MaxQueueSize == 0 {
		return 0
	}
	return float64(pm.QueueSize) / float64(pm.MaxQueueSize) * 100
}

// Health check methods
func (dhc *DefaultHealthChecker) IsHealthy(workerID int) bool {
	dhc.mutex.RLock()
	defer dhc.mutex.RUnlock()
	
	metrics, exists := dhc.workerMetrics[workerID]
	if !exists {
		return true // New worker, assume healthy
	}
	
	// Consider unhealthy if no activity for 5 minutes
	if time.Since(metrics.LastSeen) > 5*time.Minute {
		return false
	}
	
	// Consider unhealthy if failure rate > 50%
	if metrics.TasksFailed > 0 {
		failureRate := float64(metrics.TasksFailed) / float64(metrics.TasksProcessed + metrics.TasksFailed)
		if failureRate > 0.5 {
			return false
		}
	}
	
	return metrics.IsHealthy
}

func (dhc *DefaultHealthChecker) RecordMetrics(workerID int, duration time.Duration, success bool) {
	dhc.mutex.Lock()
	defer dhc.mutex.Unlock()
	
	metrics, exists := dhc.workerMetrics[workerID]
	if !exists {
		metrics = &WorkerMetrics{
			IsHealthy: true,
		}
		dhc.workerMetrics[workerID] = metrics
	}
	
	metrics.LastSeen = time.Now()
	
	if success {
		metrics.TasksProcessed++
	} else {
		metrics.TasksFailed++
	}
	
	// Update average duration (simple moving average)
	if metrics.TasksProcessed > 0 {
		total := metrics.TasksProcessed + metrics.TasksFailed
		metrics.AvgDuration = (metrics.AvgDuration*time.Duration(total-1) + duration) / time.Duration(total)
	}
}

// PriorityQueue implements a priority-based job queue
type PriorityQueue struct {
	jobs []Job
	mutex sync.RWMutex
}

// NewPriorityQueue creates a priority queue
func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		jobs: make([]Job, 0),
	}
}

// Push adds a job to the priority queue
func (pq *PriorityQueue) Push(job Job) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()
	
	pq.jobs = append(pq.jobs, job)
	pq.bubbleUp(len(pq.jobs) - 1)
}

// Pop removes and returns the highest priority job
func (pq *PriorityQueue) Pop() Job {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()
	
	if len(pq.jobs) == 0 {
		return nil
	}
	
	job := pq.jobs[0]
	last := len(pq.jobs) - 1
	pq.jobs[0] = pq.jobs[last]
	pq.jobs = pq.jobs[:last]
	
	if len(pq.jobs) > 0 {
		pq.bubbleDown(0)
	}
	
	return job
}

// Len returns the number of jobs in the queue
func (pq *PriorityQueue) Len() int {
	pq.mutex.RLock()
	defer pq.mutex.RUnlock()
	return len(pq.jobs)
}

// bubbleUp maintains heap property when inserting
func (pq *PriorityQueue) bubbleUp(index int) {
	for index > 0 {
		parent := (index - 1) / 2
		if pq.jobs[index].Priority() <= pq.jobs[parent].Priority() {
			break
		}
		pq.jobs[index], pq.jobs[parent] = pq.jobs[parent], pq.jobs[index]
		index = parent
	}
}

// bubbleDown maintains heap property when removing
func (pq *PriorityQueue) bubbleDown(index int) {
	for {
		left := 2*index + 1
		right := 2*index + 2
		largest := index
		
		if left < len(pq.jobs) && pq.jobs[left].Priority() > pq.jobs[largest].Priority() {
			largest = left
		}
		
		if right < len(pq.jobs) && pq.jobs[right].Priority() > pq.jobs[largest].Priority() {
			largest = right
		}
		
		if largest == index {
			break
		}
		
		pq.jobs[index], pq.jobs[largest] = pq.jobs[largest], pq.jobs[index]
		index = largest
	}
}

// AdaptiveWorkerPool adjusts worker count based on queue size and performance
type AdaptiveWorkerPool struct {
	*WorkerPool
	minWorkers    int
	maxWorkers    int
	scaleUpThreshold   float64
	scaleDownThreshold float64
	lastScaleTime      time.Time
	scaleCooldown      time.Duration
}

// NewAdaptiveWorkerPool creates an adaptive worker pool
func NewAdaptiveWorkerPool(minWorkers, maxWorkers int, queueSize int) *AdaptiveWorkerPool {
	pool := NewWorkerPool(minWorkers, queueSize)
	
	return &AdaptiveWorkerPool{
		WorkerPool:         pool,
		minWorkers:         minWorkers,
		maxWorkers:         maxWorkers,
		scaleUpThreshold:   0.8,  // Scale up when queue is 80% full
		scaleDownThreshold: 0.2,  // Scale down when queue is 20% full
		scaleCooldown:      time.Minute * 2,
	}
}

// Monitor continuously monitors and adjusts worker count
func (awp *AdaptiveWorkerPool) Monitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			awp.adjustWorkers()
		case <-ctx.Done():
			return
		}
	}
}

// adjustWorkers adjusts the number of workers based on current metrics
func (awp *AdaptiveWorkerPool) adjustWorkers() {
	if time.Since(awp.lastScaleTime) < awp.scaleCooldown {
		return
	}
	
	metrics := awp.GetMetrics()
	utilization := metrics.QueueUtilization() / 100.0
	
	if utilization > awp.scaleUpThreshold && awp.workers < awp.maxWorkers {
		// Scale up
		newWorkers := awp.workers + 1
		if newWorkers > awp.maxWorkers {
			newWorkers = awp.maxWorkers
		}
		awp.scaleWorkers(newWorkers)
	} else if utilization < awp.scaleDownThreshold && awp.workers > awp.minWorkers {
		// Scale down
		newWorkers := awp.workers - 1
		if newWorkers < awp.minWorkers {
			newWorkers = awp.minWorkers
		}
		awp.scaleWorkers(newWorkers)
	}
}

// scaleWorkers changes the number of active workers
func (awp *AdaptiveWorkerPool) scaleWorkers(targetWorkers int) {
	// This is a simplified implementation
	// In production, you'd need more sophisticated worker lifecycle management
	awp.workers = targetWorkers
	awp.lastScaleTime = time.Now()
}

// Example job implementation
type BasicJob struct {
	id          string
	task        func(ctx context.Context) error
	priority    int
	deadline    time.Time
	maxRetries  int
	retryable   bool
}

func NewBasicJob(id string, task func(ctx context.Context) error) *BasicJob {
	return &BasicJob{
		id:         id,
		task:       task,
		priority:   0,
		maxRetries: 3,
		retryable:  true,
	}
}

func (bj *BasicJob) ID() string                   { return bj.id }
func (bj *BasicJob) Execute(ctx context.Context) error { return bj.task(ctx) }
func (bj *BasicJob) Priority() int                { return bj.priority }
func (bj *BasicJob) Deadline() time.Time          { return bj.deadline }
func (bj *BasicJob) Retry() bool                  { return bj.retryable }
func (bj *BasicJob) MaxRetries() int              { return bj.maxRetries }

func (bj *BasicJob) SetPriority(p int)             { bj.priority = p }
func (bj *BasicJob) SetDeadline(d time.Time)       { bj.deadline = d }
func (bj *BasicJob) SetMaxRetries(r int)           { bj.maxRetries = r }
func (bj *BasicJob) SetRetryable(retryable bool)   { bj.retryable = retryable }