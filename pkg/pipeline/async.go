package pipeline

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// PipelineStage represents a single stage in the processing pipeline
type PipelineStage interface {
	Process(ctx context.Context, data interface{}) (interface{}, error)
	Name() string
}

// PipelineConfig holds configuration for the async pipeline
type PipelineConfig struct {
	BufferSize       int           `json:"buffer_size"`
	WorkerCount      int           `json:"worker_count"`
	Timeout          time.Duration `json:"timeout"`
	RetryAttempts    int           `json:"retry_attempts"`
	RetryBackoff     time.Duration `json:"retry_backoff"`
	EnableMetrics    bool          `json:"enable_metrics"`
	EnableProfiling  bool          `json:"enable_profiling"`
	MaxMemoryUsage   int64         `json:"max_memory_usage"`
}

// DefaultPipelineConfig returns sensible defaults
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		BufferSize:      1000,
		WorkerCount:     10,
		Timeout:         30 * time.Second,
		RetryAttempts:   3,
		RetryBackoff:    time.Second,
		EnableMetrics:   true,
		EnableProfiling: false,
		MaxMemoryUsage:  1024 * 1024 * 1024, // 1GB
	}
}

// PipelineMetrics tracks pipeline performance
type PipelineMetrics struct {
	ItemsProcessed   int64         `json:"items_processed"`
	ItemsSuccess     int64         `json:"items_success"`
	ItemsFailed      int64         `json:"items_failed"`
	ItemsRetried     int64         `json:"items_retried"`
	AverageLatency   time.Duration `json:"average_latency"`
	TotalLatency     time.Duration `json:"total_latency"`
	ThroughputPerSec float64       `json:"throughput_per_sec"`
	QueueLength      int64         `json:"queue_length"`
	ActiveWorkers    int64         `json:"active_workers"`
	MemoryUsage      int64         `json:"memory_usage"`
	StartTime        time.Time     `json:"start_time"`
	mu               sync.RWMutex
}

// ProcessingResult represents the result of processing an item
type ProcessingResult struct {
	ID        string        `json:"id"`
	Input     interface{}   `json:"input"`
	Output    interface{}   `json:"output"`
	Error     error         `json:"error"`
	Duration  time.Duration `json:"duration"`
	Retries   int           `json:"retries"`
	StageTime map[string]time.Duration `json:"stage_time"`
}

// PipelineItem represents an item being processed through the pipeline
type PipelineItem struct {
	ID          string      `json:"id"`
	Data        interface{} `json:"data"`
	Context     context.Context
	ResultChan  chan *ProcessingResult
	CreatedAt   time.Time   `json:"created_at"`
	Retries     int         `json:"retries"`
	MaxRetries  int         `json:"max_retries"`
}

// AsyncPipeline represents an asynchronous processing pipeline
type AsyncPipeline struct {
	config      PipelineConfig
	stages      []PipelineStage
	inputChan   chan *PipelineItem
	outputChan  chan *ProcessingResult
	workers     []*PipelineWorker
	metrics     *PipelineMetrics
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
}

// NewAsyncPipeline creates a new async processing pipeline
func NewAsyncPipeline(config PipelineConfig, stages []PipelineStage) *AsyncPipeline {
	ctx, cancel := context.WithCancel(context.Background())
	
	pipeline := &AsyncPipeline{
		config:     config,
		stages:     stages,
		inputChan:  make(chan *PipelineItem, config.BufferSize),
		outputChan: make(chan *ProcessingResult, config.BufferSize),
		workers:    make([]*PipelineWorker, config.WorkerCount),
		metrics: &PipelineMetrics{
			StartTime: time.Now(),
		},
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start workers
	for i := 0; i < config.WorkerCount; i++ {
		worker := NewPipelineWorker(i, pipeline.inputChan, pipeline.outputChan, stages, config)
		pipeline.workers[i] = worker
		pipeline.wg.Add(1)
		go worker.Start(ctx, &pipeline.wg)
	}

	// Start metrics collector
	if config.EnableMetrics {
		go pipeline.metricsCollector()
	}

	// Start memory monitor
	go pipeline.memoryMonitor()

	return pipeline
}

// Submit submits an item for processing
func (p *AsyncPipeline) Submit(ctx context.Context, id string, data interface{}) (<-chan *ProcessingResult, error) {
	resultChan := make(chan *ProcessingResult, 1)
	
	item := &PipelineItem{
		ID:         id,
		Data:       data,
		Context:    ctx,
		ResultChan: resultChan,
		CreatedAt:  time.Now(),
		Retries:    0,
		MaxRetries: p.config.RetryAttempts,
	}

	select {
	case p.inputChan <- item:
		atomic.AddInt64(&p.metrics.QueueLength, 1)
		return resultChan, nil
	case <-ctx.Done():
		close(resultChan)
		return nil, ctx.Err()
	case <-p.ctx.Done():
		close(resultChan)
		return nil, fmt.Errorf("pipeline is shutting down")
	default:
		close(resultChan)
		return nil, fmt.Errorf("pipeline queue is full")
	}
}

// SubmitBatch submits multiple items for processing
func (p *AsyncPipeline) SubmitBatch(ctx context.Context, items map[string]interface{}) (map[string]<-chan *ProcessingResult, error) {
	results := make(map[string]<-chan *ProcessingResult)
	
	for id, data := range items {
		resultChan, err := p.Submit(ctx, id, data)
		if err != nil {
			// Clean up already submitted items
			for _, ch := range results {
				go func(ch <-chan *ProcessingResult) {
					<-ch // Drain the channel
				}(ch)
			}
			return nil, fmt.Errorf("failed to submit item %s: %w", id, err)
		}
		results[id] = resultChan
	}
	
	return results, nil
}

// GetMetrics returns current pipeline metrics
func (p *AsyncPipeline) GetMetrics() PipelineMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()
	
	metrics := *p.metrics
	metrics.QueueLength = int64(len(p.inputChan))
	
	// Calculate throughput
	elapsed := time.Since(metrics.StartTime)
	if elapsed > 0 {
		metrics.ThroughputPerSec = float64(metrics.ItemsProcessed) / elapsed.Seconds()
	}
	
	// Calculate average latency
	if metrics.ItemsProcessed > 0 {
		metrics.AverageLatency = time.Duration(int64(metrics.TotalLatency) / metrics.ItemsProcessed)
	}
	
	return metrics
}

// GetStageMetrics returns metrics for each pipeline stage
func (p *AsyncPipeline) GetStageMetrics() map[string]interface{} {
	stageMetrics := make(map[string]interface{})
	
	for _, stage := range p.stages {
		stageMetrics[stage.Name()] = map[string]interface{}{
			"name": stage.Name(),
		}
	}
	
	return stageMetrics
}

// Shutdown gracefully shuts down the pipeline
func (p *AsyncPipeline) Shutdown(timeout time.Duration) error {
	// Close input channel to signal workers to stop
	close(p.inputChan)
	
	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		p.cancel()
		close(p.outputChan)
		return nil
	case <-time.After(timeout):
		p.cancel()
		return fmt.Errorf("shutdown timeout exceeded")
	}
}

// metricsCollector periodically collects and updates metrics
func (p *AsyncPipeline) metricsCollector() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			p.updateMetrics()
		case <-p.ctx.Done():
			return
		}
	}
}

// updateMetrics updates pipeline metrics
func (p *AsyncPipeline) updateMetrics() {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()
	
	activeWorkers := int64(0)
	for _, worker := range p.workers {
		if worker.IsActive() {
			activeWorkers++
		}
	}
	p.metrics.ActiveWorkers = activeWorkers
	
	// Update memory usage (placeholder for now)
	p.metrics.MemoryUsage = 0
}

// memoryMonitor monitors memory usage and triggers GC if needed
func (p *AsyncPipeline) memoryMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			if int64(stats.HeapInuse) > p.config.MaxMemoryUsage {
				runtime.GC()
			}
		case <-p.ctx.Done():
			return
		}
	}
}

// PipelineWorker processes items through the pipeline stages
type PipelineWorker struct {
	id         int
	inputChan  chan *PipelineItem
	outputChan chan<- *ProcessingResult
	stages     []PipelineStage
	config     PipelineConfig
	active     int64
}

// NewPipelineWorker creates a new pipeline worker
func NewPipelineWorker(id int, inputChan chan *PipelineItem, outputChan chan<- *ProcessingResult, 
	stages []PipelineStage, config PipelineConfig) *PipelineWorker {
	return &PipelineWorker{
		id:         id,
		inputChan:  inputChan,
		outputChan: outputChan,
		stages:     stages,
		config:     config,
	}
}

// Start starts the worker
func (w *PipelineWorker) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for {
		select {
		case item, ok := <-w.inputChan:
			if !ok {
				return // Channel closed
			}
			w.processItem(ctx, item)
		case <-ctx.Done():
			return
		}
	}
}

// IsActive returns whether the worker is currently processing an item
func (w *PipelineWorker) IsActive() bool {
	return atomic.LoadInt64(&w.active) > 0
}

// processItem processes a single item through all pipeline stages
func (w *PipelineWorker) processItem(ctx context.Context, item *PipelineItem) {
	atomic.StoreInt64(&w.active, 1)
	defer atomic.StoreInt64(&w.active, 0)
	
	startTime := time.Now()
	stageTimings := make(map[string]time.Duration)
	
	result := &ProcessingResult{
		ID:        item.ID,
		Input:     item.Data,
		Retries:   item.Retries,
		StageTime: stageTimings,
	}
	
	// Create timeout context
	processCtx, cancel := context.WithTimeout(ctx, w.config.Timeout)
	defer cancel()
	
	// Process through all stages
	currentData := item.Data
	var err error
	
	for _, stage := range w.stages {
		stageStart := time.Now()
		
		currentData, err = stage.Process(processCtx, currentData)
		if err != nil {
			result.Error = fmt.Errorf("stage %s failed: %w", stage.Name(), err)
			break
		}
		
		stageTimings[stage.Name()] = time.Since(stageStart)
	}
	
	result.Output = currentData
	result.Duration = time.Since(startTime)
	
	// Handle retries
	if err != nil && item.Retries < item.MaxRetries {
		item.Retries++
		item.Data = result.Input // Reset to original input
		
		// Schedule retry with backoff
		go func() {
			backoff := w.config.RetryBackoff * time.Duration(item.Retries)
			time.Sleep(backoff)
			
			select {
			case w.inputChan <- item:
				// Item requeued successfully
			case <-ctx.Done():
				// Context cancelled, send final result
				w.sendResult(result, item.ResultChan)
			}
		}()
		return
	}
	
	w.sendResult(result, item.ResultChan)
}

// sendResult sends the processing result
func (w *PipelineWorker) sendResult(result *ProcessingResult, resultChan chan *ProcessingResult) {
	select {
	case resultChan <- result:
		close(resultChan)
	default:
		// Channel is full or closed, result will be lost
		close(resultChan)
	}
}

// Common pipeline stages

// ValidationStage validates input data
type ValidationStage struct {
	validator func(interface{}) error
}

// NewValidationStage creates a new validation stage
func NewValidationStage(validator func(interface{}) error) *ValidationStage {
	return &ValidationStage{validator: validator}
}

func (v *ValidationStage) Process(ctx context.Context, data interface{}) (interface{}, error) {
	if err := v.validator(data); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	return data, nil
}

func (v *ValidationStage) Name() string {
	return "validation"
}

// TransformationStage transforms data from one format to another
type TransformationStage struct {
	transformer func(interface{}) (interface{}, error)
	name        string
}

// NewTransformationStage creates a new transformation stage
func NewTransformationStage(name string, transformer func(interface{}) (interface{}, error)) *TransformationStage {
	return &TransformationStage{
		transformer: transformer,
		name:        name,
	}
}

func (t *TransformationStage) Process(ctx context.Context, data interface{}) (interface{}, error) {
	return t.transformer(data)
}

func (t *TransformationStage) Name() string {
	return t.name
}

// PersistenceStage saves data to a persistent store
type PersistenceStage struct {
	persister func(context.Context, interface{}) error
}

// NewPersistenceStage creates a new persistence stage
func NewPersistenceStage(persister func(context.Context, interface{}) error) *PersistenceStage {
	return &PersistenceStage{persister: persister}
}

func (p *PersistenceStage) Process(ctx context.Context, data interface{}) (interface{}, error) {
	if err := p.persister(ctx, data); err != nil {
		return nil, fmt.Errorf("persistence failed: %w", err)
	}
	return data, nil
}

func (p *PersistenceStage) Name() string {
	return "persistence"
}

// ParallelStage processes multiple sub-stages in parallel
type ParallelStage struct {
	stages []PipelineStage
	name   string
}

// NewParallelStage creates a new parallel processing stage
func NewParallelStage(name string, stages []PipelineStage) *ParallelStage {
	return &ParallelStage{
		stages: stages,
		name:   name,
	}
}

func (p *ParallelStage) Process(ctx context.Context, data interface{}) (interface{}, error) {
	type result struct {
		output interface{}
		err    error
		index  int
	}
	
	results := make(chan result, len(p.stages))
	
	// Start all stages in parallel
	for i, stage := range p.stages {
		go func(index int, s PipelineStage) {
			output, err := s.Process(ctx, data)
			results <- result{output: output, err: err, index: index}
		}(i, stage)
	}
	
	// Collect results
	outputs := make([]interface{}, len(p.stages))
	var errors []error
	
	for i := 0; i < len(p.stages); i++ {
		select {
		case res := <-results:
			if res.err != nil {
				errors = append(errors, fmt.Errorf("stage %s failed: %w", p.stages[res.index].Name(), res.err))
			} else {
				outputs[res.index] = res.output
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	if len(errors) > 0 {
		return nil, fmt.Errorf("parallel stage failures: %v", errors)
	}
	
	return outputs, nil
}

func (p *ParallelStage) Name() string {
	return p.name
}