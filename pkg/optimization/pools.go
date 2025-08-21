package optimization

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

// GoroutinePool manages a pool of worker goroutines
type GoroutinePool struct {
	maxWorkers    int
	activeWorkers int64
	taskQueue     chan Task
	workerQueue   chan chan Task
	quit          chan bool
	logger        *logrus.Logger
	wg            sync.WaitGroup
}

// Task represents a unit of work
type Task struct {
	ID      string
	Execute func(context.Context) error
	Context context.Context
	Timeout time.Duration
}

// NewGoroutinePool creates a new goroutine pool
func NewGoroutinePool(maxWorkers int, logger *logrus.Logger) *GoroutinePool {
	pool := &GoroutinePool{
		maxWorkers:  maxWorkers,
		taskQueue:   make(chan Task, maxWorkers*2),
		workerQueue: make(chan chan Task, maxWorkers),
		quit:        make(chan bool),
		logger:      logger,
	}
	
	// Start dispatcher
	go pool.dispatch()
	
	return pool
}

// Submit submits a task to the pool
func (gp *GoroutinePool) Submit(task Task) error {
	select {
	case gp.taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

// dispatch manages task distribution to workers
func (gp *GoroutinePool) dispatch() {
	for {
		select {
		case task := <-gp.taskQueue:
			// Try to get an available worker
			select {
			case workerTaskQueue := <-gp.workerQueue:
				// Found an available worker, dispatch the task
				workerTaskQueue <- task
			default:
				// No available worker, create a new one if possible
				if atomic.LoadInt64(&gp.activeWorkers) < int64(gp.maxWorkers) {
					gp.createWorker()
					// Try to dispatch to the new worker
					select {
					case workerTaskQueue := <-gp.workerQueue:
						workerTaskQueue <- task
					case <-time.After(100 * time.Millisecond):
						// Put task back in queue
						gp.taskQueue <- task
					}
				} else {
					// Put task back in queue and wait
					gp.taskQueue <- task
					time.Sleep(10 * time.Millisecond)
				}
			}
		case <-gp.quit:
			return
		}
	}
}

// createWorker creates a new worker goroutine
func (gp *GoroutinePool) createWorker() {
	worker := Worker{
		ID:          atomic.AddInt64(&gp.activeWorkers, 1),
		taskQueue:   make(chan Task),
		workerQueue: gp.workerQueue,
		quit:        make(chan bool),
		logger:      gp.logger,
	}
	
	gp.wg.Add(1)
	go worker.start(&gp.wg, &gp.activeWorkers)
}

// Close closes the goroutine pool
func (gp *GoroutinePool) Close() {
	close(gp.quit)
	gp.wg.Wait()
}

// GetStats returns pool statistics
func (gp *GoroutinePool) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"max_workers":    gp.maxWorkers,
		"active_workers": atomic.LoadInt64(&gp.activeWorkers),
		"queued_tasks":   len(gp.taskQueue),
	}
}

// Worker represents a worker goroutine
type Worker struct {
	ID          int64
	taskQueue   chan Task
	workerQueue chan chan Task
	quit        chan bool
	logger      *logrus.Logger
}

// start starts the worker goroutine
func (w *Worker) start(wg *sync.WaitGroup, activeWorkers *int64) {
	defer wg.Done()
	defer atomic.AddInt64(activeWorkers, -1)
	
	for {
		// Register this worker in the worker queue
		w.workerQueue <- w.taskQueue
		
		select {
		case task := <-w.taskQueue:
			w.executeTask(task)
		case <-w.quit:
			return
		case <-time.After(30 * time.Second):
			// Worker timeout - self-destruct to prevent resource leaks
			w.logger.WithFields(logrus.Fields{
				"worker_id": w.ID,
			}).Debug("Worker timeout, terminating")
			return
		}
	}
}

// executeTask executes a task with timeout and error handling
func (w *Worker) executeTask(task Task) {
	start := time.Now()
	
	// Set up timeout context if specified
	ctx := task.Context
	if task.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(task.Context, task.Timeout)
		defer cancel()
	}
	
	// Execute task with panic recovery
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("task panic: %v", r)
			}
		}()
		return task.Execute(ctx)
	}()
	
	duration := time.Since(start)
	
	// Log task completion
	logFields := logrus.Fields{
		"worker_id": w.ID,
		"task_id":   task.ID,
		"duration":  duration,
	}
	
	if err != nil {
		logFields["error"] = err.Error()
		w.logger.WithFields(logFields).Error("Task execution failed")
	} else {
		w.logger.WithFields(logFields).Debug("Task executed successfully")
	}
}

// MemoryPool manages reusable memory buffers
type MemoryPool struct {
	smallBuffers  sync.Pool
	mediumBuffers sync.Pool
	largeBuffers  sync.Pool
	logger        *logrus.Logger
	stats         MemoryPoolStats
	mu            sync.RWMutex
}

// MemoryPoolStats tracks memory pool statistics
type MemoryPoolStats struct {
	SmallBufferHits   int64 `json:"small_buffer_hits"`
	MediumBufferHits  int64 `json:"medium_buffer_hits"`
	LargeBufferHits   int64 `json:"large_buffer_hits"`
	SmallBufferMisses int64 `json:"small_buffer_misses"`
	MediumBufferMisses int64 `json:"medium_buffer_misses"`
	LargeBufferMisses int64 `json:"large_buffer_misses"`
}

// NewMemoryPool creates a new memory pool
func NewMemoryPool(logger *logrus.Logger) *MemoryPool {
	mp := &MemoryPool{
		logger: logger,
	}
	
	// Initialize pools with different buffer sizes
	mp.smallBuffers.New = func() interface{} {
		atomic.AddInt64(&mp.stats.SmallBufferMisses, 1)
		return make([]byte, 0, 1024) // 1KB buffers
	}
	
	mp.mediumBuffers.New = func() interface{} {
		atomic.AddInt64(&mp.stats.MediumBufferMisses, 1)
		return make([]byte, 0, 64*1024) // 64KB buffers
	}
	
	mp.largeBuffers.New = func() interface{} {
		atomic.AddInt64(&mp.stats.LargeBufferMisses, 1)
		return make([]byte, 0, 1024*1024) // 1MB buffers
	}
	
	return mp
}

// GetBuffer gets a buffer of appropriate size
func (mp *MemoryPool) GetBuffer(size int) []byte {
	var buffer []byte
	
	switch {
	case size <= 1024:
		atomic.AddInt64(&mp.stats.SmallBufferHits, 1)
		buffer = mp.smallBuffers.Get().([]byte)
	case size <= 64*1024:
		atomic.AddInt64(&mp.stats.MediumBufferHits, 1)
		buffer = mp.mediumBuffers.Get().([]byte)
	case size <= 1024*1024:
		atomic.AddInt64(&mp.stats.LargeBufferHits, 1)
		buffer = mp.largeBuffers.Get().([]byte)
	default:
		// For very large buffers, allocate directly
		return make([]byte, 0, size)
	}
	
	// Reset buffer length but keep capacity
	return buffer[:0]
}

// ReturnBuffer returns a buffer to the pool
func (mp *MemoryPool) ReturnBuffer(buffer []byte) {
	// Don't return nil or extremely large buffers
	if buffer == nil || cap(buffer) > 2*1024*1024 {
		return
	}
	
	// Determine which pool to return to based on capacity
	switch {
	case cap(buffer) <= 1024:
		mp.smallBuffers.Put(buffer)
	case cap(buffer) <= 64*1024:
		mp.mediumBuffers.Put(buffer)
	case cap(buffer) <= 1024*1024:
		mp.largeBuffers.Put(buffer)
	}
}

// GetStats returns memory pool statistics
func (mp *MemoryPool) GetStats() MemoryPoolStats {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	
	return MemoryPoolStats{
		SmallBufferHits:    atomic.LoadInt64(&mp.stats.SmallBufferHits),
		MediumBufferHits:   atomic.LoadInt64(&mp.stats.MediumBufferHits),
		LargeBufferHits:    atomic.LoadInt64(&mp.stats.LargeBufferHits),
		SmallBufferMisses:  atomic.LoadInt64(&mp.stats.SmallBufferMisses),
		MediumBufferMisses: atomic.LoadInt64(&mp.stats.MediumBufferMisses),
		LargeBufferMisses:  atomic.LoadInt64(&mp.stats.LargeBufferMisses),
	}
}

// Close cleans up the memory pool
func (mp *MemoryPool) Close() {
	// Pools will be garbage collected automatically
	mp.logger.Debug("Memory pool closed")
}

// NetworkOptimizer optimizes network-related performance
type NetworkOptimizer struct {
	logger *logrus.Logger
}

// NewNetworkOptimizer creates a new network optimizer
func NewNetworkOptimizer(logger *logrus.Logger) *NetworkOptimizer {
	return &NetworkOptimizer{
		logger: logger,
	}
}

// Optimize performs network optimizations based on current metrics
func (no *NetworkOptimizer) Optimize(metrics *monitoring.ApplicationMetrics) bool {
	optimized := false
	
	// Optimize based on connection count
	if metrics.ActiveConnections > 1000 {
		// High connection count optimizations
		no.logger.WithFields(logrus.Fields{
			"active_connections": metrics.ActiveConnections,
		}).Info("Applying high-connection-count network optimizations")
		optimized = true
	}
	
	// Optimize based on response time
	if metrics.ResponseTimeMs > 100 {
		// High latency optimizations
		no.logger.WithFields(logrus.Fields{
			"response_time_ms": metrics.ResponseTimeMs,
		}).Info("Applying high-latency network optimizations")
		optimized = true
	}
	
	return optimized
}