package worker

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Task represents a unit of work
type Task struct {
	ID       string
	Data     interface{}
	Handler  TaskHandler
	Priority int
	Retries  int
	MaxRetries int
	CreatedAt time.Time
}

// TaskHandler defines the interface for task handlers
type TaskHandler interface {
	Handle(ctx context.Context, data interface{}) error
}

// TaskHandlerFunc is a function adapter for TaskHandler
type TaskHandlerFunc func(ctx context.Context, data interface{}) error

func (f TaskHandlerFunc) Handle(ctx context.Context, data interface{}) error {
	return f(ctx, data)
}

// Result represents the result of a task execution
type Result struct {
	TaskID    string
	Success   bool
	Error     error
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

// PoolConfig holds configuration for the worker pool
type PoolConfig struct {
	WorkerCount   int
	QueueSize     int
	MaxRetries    int
	RetryDelay    time.Duration
	RetryBackoff  float64
	Timeout       time.Duration
	EnableMetrics bool
}

// Pool represents a worker pool
type Pool struct {
	config    PoolConfig
	taskQueue chan *Task
	results   chan *Result
	workers   []*Worker
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	metrics   *PoolMetrics
	mu        sync.RWMutex
}

// PoolMetrics holds metrics for the worker pool
type PoolMetrics struct {
	TasksSubmitted   int64 `json:"tasks_submitted"`
	TasksCompleted   int64 `json:"tasks_completed"`
	TasksFailed      int64 `json:"tasks_failed"`
	TasksRetried     int64 `json:"tasks_retried"`
	AverageExecTime  time.Duration `json:"average_exec_time"`
	QueueLength      int `json:"queue_length"`
	ActiveWorkers    int `json:"active_workers"`
	mu               sync.RWMutex
}

// NewPool creates a new worker pool
func NewPool(config PoolConfig) *Pool {
	if config.WorkerCount <= 0 {
		config.WorkerCount = runtime.NumCPU()
	}
	if config.QueueSize <= 0 {
		config.QueueSize = config.WorkerCount * 100
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = time.Second
	}
	if config.RetryBackoff <= 0 {
		config.RetryBackoff = 2.0
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &Pool{
		config:    config,
		taskQueue: make(chan *Task, config.QueueSize),
		results:   make(chan *Result, config.QueueSize),
		workers:   make([]*Worker, config.WorkerCount),
		ctx:       ctx,
		cancel:    cancel,
		metrics:   &PoolMetrics{},
	}

	// Start workers
	for i := 0; i < config.WorkerCount; i++ {
		worker := NewWorker(i, pool.taskQueue, pool.results, &pool.wg)
		pool.workers[i] = worker
		pool.wg.Add(1)
		go worker.Start(ctx)
	}

	// Start result processor
	go pool.processResults()

	return pool
}

// Submit submits a task to the worker pool
func (p *Pool) Submit(task *Task) error {
	if task.MaxRetries == 0 {
		task.MaxRetries = p.config.MaxRetries
	}
	task.CreatedAt = time.Now()

	select {
	case p.taskQueue <- task:
		p.metrics.mu.Lock()
		p.metrics.TasksSubmitted++
		p.metrics.mu.Unlock()
		return nil
	case <-p.ctx.Done():
		return fmt.Errorf("pool is shutting down")
	default:
		return fmt.Errorf("task queue is full")
	}
}

// SubmitFunc submits a function as a task
func (p *Pool) SubmitFunc(id string, priority int, fn TaskHandlerFunc, data interface{}) error {
	task := &Task{
		ID:       id,
		Data:     data,
		Handler:  fn,
		Priority: priority,
	}
	return p.Submit(task)
}

// Results returns the results channel
func (p *Pool) Results() <-chan *Result {
	return p.results
}

// GetMetrics returns current pool metrics
func (p *Pool) GetMetrics() PoolMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	metrics := *p.metrics
	metrics.QueueLength = len(p.taskQueue)
	metrics.ActiveWorkers = p.getActiveWorkerCount()

	return metrics
}

// Shutdown gracefully shuts down the worker pool
func (p *Pool) Shutdown(timeout time.Duration) error {
	// Close the task queue to signal no more tasks
	close(p.taskQueue)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.cancel()
		return nil
	case <-time.After(timeout):
		p.cancel()
		return fmt.Errorf("shutdown timeout exceeded")
	}
}

// processResults processes task results and updates metrics
func (p *Pool) processResults() {
	for result := range p.results {
		p.metrics.mu.Lock()
		if result.Success {
			p.metrics.TasksCompleted++
		} else {
			p.metrics.TasksFailed++
		}
		p.metrics.mu.Unlock()
	}
}

// getActiveWorkerCount returns the number of active workers
func (p *Pool) getActiveWorkerCount() int {
	count := 0
	for _, worker := range p.workers {
		if worker.IsActive() {
			count++
		}
	}
	return count
}

// Worker represents a single worker in the pool
type Worker struct {
	id        int
	taskQueue <-chan *Task
	results   chan<- *Result
	wg        *sync.WaitGroup
	active    bool
	mu        sync.RWMutex
}

// NewWorker creates a new worker
func NewWorker(id int, taskQueue <-chan *Task, results chan<- *Result, wg *sync.WaitGroup) *Worker {
	return &Worker{
		id:        id,
		taskQueue: taskQueue,
		results:   results,
		wg:        wg,
	}
}

// Start starts the worker
func (w *Worker) Start(ctx context.Context) {
	defer w.wg.Done()

	for {
		select {
		case task, ok := <-w.taskQueue:
			if !ok {
				return // Channel closed, exit
			}
			w.processTask(ctx, task)
		case <-ctx.Done():
			return
		}
	}
}

// IsActive returns whether the worker is currently processing a task
func (w *Worker) IsActive() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.active
}

// processTask processes a single task
func (w *Worker) processTask(ctx context.Context, task *Task) {
	w.mu.Lock()
	w.active = true
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.active = false
		w.mu.Unlock()
	}()

	startTime := time.Now()
	
	// Create task context with timeout
	taskCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Execute task
	err := task.Handler.Handle(taskCtx, task.Data)
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	result := &Result{
		TaskID:    task.ID,
		Success:   err == nil,
		Error:     err,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
	}

	// Handle retries
	if err != nil && task.Retries < task.MaxRetries {
		task.Retries++
		
		// Calculate retry delay with exponential backoff
		delay := time.Duration(float64(time.Second) * float64(task.Retries) * 2.0)
		
		// Schedule retry
		go func() {
			time.Sleep(delay)
			select {
			case w.taskQueue <- task:
				// Task requeued successfully
			case <-ctx.Done():
				// Context cancelled, don't retry
			}
		}()
	}

	// Send result
	select {
	case w.results <- result:
	case <-ctx.Done():
		return
	}
}

// PriorityQueue implements a priority queue for tasks
type PriorityQueue struct {
	tasks []*Task
	mu    sync.RWMutex
}

// NewPriorityQueue creates a new priority queue
func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		tasks: make([]*Task, 0),
	}
}

// Push adds a task to the priority queue
func (pq *PriorityQueue) Push(task *Task) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	pq.tasks = append(pq.tasks, task)
	pq.heapifyUp(len(pq.tasks) - 1)
}

// Pop removes and returns the highest priority task
func (pq *PriorityQueue) Pop() *Task {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.tasks) == 0 {
		return nil
	}

	task := pq.tasks[0]
	lastIndex := len(pq.tasks) - 1
	pq.tasks[0] = pq.tasks[lastIndex]
	pq.tasks = pq.tasks[:lastIndex]

	if len(pq.tasks) > 0 {
		pq.heapifyDown(0)
	}

	return task
}

// Len returns the number of tasks in the queue
func (pq *PriorityQueue) Len() int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	return len(pq.tasks)
}

// heapifyUp maintains heap property while moving up
func (pq *PriorityQueue) heapifyUp(index int) {
	if index == 0 {
		return
	}

	parentIndex := (index - 1) / 2
	if pq.tasks[index].Priority > pq.tasks[parentIndex].Priority {
		pq.tasks[index], pq.tasks[parentIndex] = pq.tasks[parentIndex], pq.tasks[index]
		pq.heapifyUp(parentIndex)
	}
}

// heapifyDown maintains heap property while moving down
func (pq *PriorityQueue) heapifyDown(index int) {
	leftChild := 2*index + 1
	rightChild := 2*index + 2
	largest := index

	if leftChild < len(pq.tasks) && pq.tasks[leftChild].Priority > pq.tasks[largest].Priority {
		largest = leftChild
	}

	if rightChild < len(pq.tasks) && pq.tasks[rightChild].Priority > pq.tasks[largest].Priority {
		largest = rightChild
	}

	if largest != index {
		pq.tasks[index], pq.tasks[largest] = pq.tasks[largest], pq.tasks[index]
		pq.heapifyDown(largest)
	}
}

// BatchProcessor handles batch processing of tasks
type BatchProcessor struct {
	pool       *Pool
	batchSize  int
	batchDelay time.Duration
	buffer     []*Task
	mu         sync.Mutex
	timer      *time.Timer
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(pool *Pool, batchSize int, batchDelay time.Duration) *BatchProcessor {
	bp := &BatchProcessor{
		pool:       pool,
		batchSize:  batchSize,
		batchDelay: batchDelay,
		buffer:     make([]*Task, 0, batchSize),
	}

	bp.timer = time.AfterFunc(batchDelay, bp.flush)
	bp.timer.Stop()

	return bp
}

// Add adds a task to the batch buffer
func (bp *BatchProcessor) Add(task *Task) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.buffer = append(bp.buffer, task)

	// Start timer if this is the first task
	if len(bp.buffer) == 1 {
		bp.timer.Reset(bp.batchDelay)
	}

	// Flush if batch is full
	if len(bp.buffer) >= bp.batchSize {
		bp.flushLocked()
	}

	return nil
}

// flush processes the current batch
func (bp *BatchProcessor) flush() {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.flushLocked()
}

// flushLocked processes the current batch (must be called with lock held)
func (bp *BatchProcessor) flushLocked() {
	if len(bp.buffer) == 0 {
		return
	}

	// Process batch
	batch := make([]*Task, len(bp.buffer))
	copy(batch, bp.buffer)
	bp.buffer = bp.buffer[:0]

	// Stop timer
	bp.timer.Stop()

	// Submit batch as a single task
	batchTask := &Task{
		ID:      fmt.Sprintf("batch-%d", time.Now().UnixNano()),
		Data:    batch,
		Handler: BatchTaskHandler{},
	}

	go bp.pool.Submit(batchTask)
}

// BatchTaskHandler handles batch tasks
type BatchTaskHandler struct{}

func (h BatchTaskHandler) Handle(ctx context.Context, data interface{}) error {
	batch, ok := data.([]*Task)
	if !ok {
		return fmt.Errorf("invalid batch data type")
	}

	// Process each task in the batch
	for _, task := range batch {
		if err := task.Handler.Handle(ctx, task.Data); err != nil {
			// Log error but continue processing other tasks
			// In a real implementation, you might want more sophisticated error handling
			continue
		}
	}

	return nil
}