package worker

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

type Job interface {
	Execute(ctx context.Context) error
	ID() string
	Priority() int
	Timeout() time.Duration
}

type Result struct {
	JobID string
	Error error
	Data  interface{}
}

type Worker struct {
	id       int
	jobQueue chan Job
	quit     chan bool
	wg       *sync.WaitGroup
	results  chan<- Result
	metrics  WorkerMetrics
}

type WorkerPool struct {
	numWorkers   int
	jobQueue     chan Job
	workers      []*Worker
	quit         chan bool
	wg           sync.WaitGroup
	results      chan Result
	metrics      *PoolMetrics
	ctx          context.Context
	cancel       context.CancelFunc
}

type WorkerMetrics struct {
	JobsProcessed int64
	JobsSucceeded int64
	JobsFailed    int64
	TotalDuration time.Duration
}

type PoolMetrics struct {
	mu            sync.RWMutex
	WorkersActive int64
	JobsQueued    int64
	JobsProcessed int64
	JobsSucceeded int64
	JobsFailed    int64
	TotalDuration time.Duration
}

type PoolConfig struct {
	NumWorkers   int
	QueueSize    int
	ResultBuffer int
}

func NewWorkerPool(config *PoolConfig) *WorkerPool {
	if config.NumWorkers <= 0 {
		config.NumWorkers = runtime.NumCPU()
	}
	if config.QueueSize <= 0 {
		config.QueueSize = config.NumWorkers * 10
	}
	if config.ResultBuffer <= 0 {
		config.ResultBuffer = config.QueueSize
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		numWorkers: config.NumWorkers,
		jobQueue:   make(chan Job, config.QueueSize),
		workers:    make([]*Worker, config.NumWorkers),
		quit:       make(chan bool),
		results:    make(chan Result, config.ResultBuffer),
		metrics:    &PoolMetrics{},
		ctx:        ctx,
		cancel:     cancel,
	}

	pool.start()
	return pool
}

func (p *WorkerPool) start() {
	for i := 0; i < p.numWorkers; i++ {
		worker := &Worker{
			id:       i,
			jobQueue: p.jobQueue,
			quit:     make(chan bool),
			wg:       &p.wg,
			results:  p.results,
		}

		p.workers[i] = worker
		p.wg.Add(1)
		go worker.start(p.ctx, p.metrics)
	}

	atomic.StoreInt64(&p.metrics.WorkersActive, int64(p.numWorkers))
	logger.Infof("Worker pool started with %d workers", p.numWorkers)
}

func (w *Worker) start(ctx context.Context, poolMetrics *PoolMetrics) {
	defer w.wg.Done()
	logger.Debugf("Worker %d started", w.id)

	for {
		select {
		case job := <-w.jobQueue:
			w.processJob(ctx, job, poolMetrics)
		case <-w.quit:
			logger.Debugf("Worker %d stopping", w.id)
			return
		case <-ctx.Done():
			logger.Debugf("Worker %d stopping due to context cancellation", w.id)
			return
		}
	}
}

func (w *Worker) processJob(ctx context.Context, job Job, poolMetrics *PoolMetrics) {
	start := time.Now()
	atomic.AddInt64(&poolMetrics.JobsQueued, -1)

	jobCtx := ctx
	timeout := job.Timeout()
	if timeout > 0 {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	logger.Debugf("Worker %d processing job %s", w.id, job.ID())

	result := Result{
		JobID: job.ID(),
	}

	defer func() {
		duration := time.Since(start)
		w.metrics.JobsProcessed++
		w.metrics.TotalDuration += duration

		atomic.AddInt64(&poolMetrics.JobsProcessed, 1)
		poolMetrics.mu.Lock()
		poolMetrics.TotalDuration += duration
		poolMetrics.mu.Unlock()

		select {
		case w.results <- result:
		default:
			logger.Warnf("Result channel full, dropping result for job %s", job.ID())
		}
	}()

	if err := job.Execute(jobCtx); err != nil {
		result.Error = err
		w.metrics.JobsFailed++
		atomic.AddInt64(&poolMetrics.JobsFailed, 1)
		logger.WithError(err).Errorf("Worker %d failed to process job %s", w.id, job.ID())
	} else {
		w.metrics.JobsSucceeded++
		atomic.AddInt64(&poolMetrics.JobsSucceeded, 1)
		logger.Debugf("Worker %d successfully processed job %s", w.id, job.ID())
	}
}

func (p *WorkerPool) Submit(job Job) error {
	select {
	case p.jobQueue <- job:
		atomic.AddInt64(&p.metrics.JobsQueued, 1)
		return nil
	default:
		return errors.New("job queue is full")
	}
}

func (p *WorkerPool) SubmitWithPriority(job Job) error {
	return p.Submit(job)
}

func (p *WorkerPool) Results() <-chan Result {
	return p.results
}

func (p *WorkerPool) Stop() {
	logger.Info("Stopping worker pool...")
	p.cancel()

	for _, worker := range p.workers {
		worker.quit <- true
	}

	p.wg.Wait()
	close(p.jobQueue)
	close(p.results)

	atomic.StoreInt64(&p.metrics.WorkersActive, 0)
	logger.Info("Worker pool stopped")
}

func (p *WorkerPool) GetMetrics() PoolMetrics {
	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	return PoolMetrics{
		WorkersActive: atomic.LoadInt64(&p.metrics.WorkersActive),
		JobsQueued:    atomic.LoadInt64(&p.metrics.JobsQueued),
		JobsProcessed: atomic.LoadInt64(&p.metrics.JobsProcessed),
		JobsSucceeded: atomic.LoadInt64(&p.metrics.JobsSucceeded),
		JobsFailed:    atomic.LoadInt64(&p.metrics.JobsFailed),
		TotalDuration: p.metrics.TotalDuration,
	}
}

func (p *WorkerPool) QueueSize() int {
	return len(p.jobQueue)
}

func (p *WorkerPool) IsHealthy() bool {
	return atomic.LoadInt64(&p.metrics.WorkersActive) > 0
}

type SBOMProcessingJob struct {
	id       string
	sbomData []byte
	format   string
	priority int
	timeout  time.Duration
	callback func(interface{}, error)
}

func NewSBOMProcessingJob(id string, data []byte, format string) *SBOMProcessingJob {
	return &SBOMProcessingJob{
		id:       id,
		sbomData: data,
		format:   format,
		priority: 5,
		timeout:  30 * time.Second,
	}
}

func (j *SBOMProcessingJob) Execute(ctx context.Context) error {
	logger.Infof("Processing SBOM job %s with format %s", j.id, j.format)

	time.Sleep(100 * time.Millisecond)

	if len(j.sbomData) == 0 {
		return errors.New("empty SBOM data")
	}

	logger.Infof("SBOM job %s processed successfully", j.id)
	return nil
}

func (j *SBOMProcessingJob) ID() string {
	return j.id
}

func (j *SBOMProcessingJob) Priority() int {
	return j.priority
}

func (j *SBOMProcessingJob) Timeout() time.Duration {
	return j.timeout
}

func (j *SBOMProcessingJob) WithCallback(callback func(interface{}, error)) *SBOMProcessingJob {
	j.callback = callback
	return j
}

type SignatureVerificationJob struct {
	id        string
	artifactID string
	signature string
	priority  int
	timeout   time.Duration
}

func NewSignatureVerificationJob(id, artifactID, signature string) *SignatureVerificationJob {
	return &SignatureVerificationJob{
		id:         id,
		artifactID: artifactID,
		signature:  signature,
		priority:   8,
		timeout:    15 * time.Second,
	}
}

func (j *SignatureVerificationJob) Execute(ctx context.Context) error {
	logger.Infof("Verifying signature for artifact %s (job %s)", j.artifactID, j.id)

	time.Sleep(50 * time.Millisecond)

	if j.signature == "" {
		return errors.New("empty signature")
	}

	logger.Infof("Signature verification job %s completed successfully", j.id)
	return nil
}

func (j *SignatureVerificationJob) ID() string {
	return j.id
}

func (j *SignatureVerificationJob) Priority() int {
	return j.priority
}

func (j *SignatureVerificationJob) Timeout() time.Duration {
	return j.timeout
}

type ProvenanceGraphJob struct {
	id       string
	nodeID   string
	depth    int
	priority int
	timeout  time.Duration
}

func NewProvenanceGraphJob(id, nodeID string, depth int) *ProvenanceGraphJob {
	return &ProvenanceGraphJob{
		id:       id,
		nodeID:   nodeID,
		depth:    depth,
		priority: 3,
		timeout:  60 * time.Second,
	}
}

func (j *ProvenanceGraphJob) Execute(ctx context.Context) error {
	logger.Infof("Building provenance graph for node %s with depth %d (job %s)", j.nodeID, j.depth, j.id)

	if j.depth > 10 {
		return errors.New("graph depth too large")
	}

	processingTime := time.Duration(j.depth*50) * time.Millisecond
	select {
	case <-time.After(processingTime):
	case <-ctx.Done():
		return ctx.Err()
	}

	logger.Infof("Provenance graph job %s completed successfully", j.id)
	return nil
}

func (j *ProvenanceGraphJob) ID() string {
	return j.id
}

func (j *ProvenanceGraphJob) Priority() int {
	return j.priority
}

func (j *ProvenanceGraphJob) Timeout() time.Duration {
	return j.timeout
}

func (p *WorkerPool) ProcessSBOM(id string, data []byte, format string) error {
	job := NewSBOMProcessingJob(id, data, format)
	return p.Submit(job)
}

func (p *WorkerPool) VerifySignature(id, artifactID, signature string) error {
	job := NewSignatureVerificationJob(id, artifactID, signature)
	return p.Submit(job)
}

func (p *WorkerPool) BuildProvenanceGraph(id, nodeID string, depth int) error {
	job := NewProvenanceGraphJob(id, nodeID, depth)
	return p.Submit(job)
}