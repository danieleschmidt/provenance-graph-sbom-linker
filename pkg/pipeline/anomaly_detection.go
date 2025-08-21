package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AnomalyDetectionConfig configures the anomaly detection system
type AnomalyDetectionConfig struct {
	WindowSize       time.Duration `yaml:"window_size"`
	SensitivityLevel float64       `yaml:"sensitivity_level"`
	ThresholdFactor  float64       `yaml:"threshold_factor"`
	MinDataPoints    int           `yaml:"min_data_points"`
}

// DefaultAnomalyDetectionConfig returns default configuration
func DefaultAnomalyDetectionConfig() AnomalyDetectionConfig {
	return AnomalyDetectionConfig{
		WindowSize:       5 * time.Minute,
		SensitivityLevel: 0.8,
		ThresholdFactor:  2.0,
		MinDataPoints:    10,
	}
}

// DataPoint represents a metric data point
type DataPoint struct {
	Metric    string                 `json:"metric"`
	Value     float64                `json:"value"`
	Timestamp time.Time              `json:"timestamp"`
	Labels    map[string]string      `json:"labels"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Metric      string                 `json:"metric"`
	Value       float64                `json:"value"`
	Expected    float64                `json:"expected"`
	Deviation   float64                `json:"deviation"`
	Severity    AnomalySeverity        `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Labels      map[string]string      `json:"labels"`
}

type AnomalySeverity string

const (
	AnomalySeverityLow      AnomalySeverity = "low"
	AnomalySeverityMedium   AnomalySeverity = "medium"
	AnomalySeverityHigh     AnomalySeverity = "high"
	AnomalySeverityCritical AnomalySeverity = "critical"
)

// AnomalyDetector detects anomalies in streaming metrics
type AnomalyDetector struct {
	config       AnomalyDetectionConfig
	logger       *logrus.Logger
	dataWindow   map[string][]DataPoint
	baselines    map[string]float64
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	anomalyChan  chan Anomaly
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config AnomalyDetectionConfig, logger *logrus.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		config:      config,
		logger:      logger,
		dataWindow:  make(map[string][]DataPoint),
		baselines:   make(map[string]float64),
		anomalyChan: make(chan Anomaly, 100),
	}
}

// Start starts the anomaly detector
func (ad *AnomalyDetector) Start(ctx context.Context) error {
	ad.ctx, ad.cancel = context.WithCancel(ctx)
	
	// Start cleanup routine
	go ad.cleanupRoutine()
	
	ad.logger.Info("Anomaly detector started")
	return nil
}

// Stop stops the anomaly detector
func (ad *AnomalyDetector) Stop() {
	if ad.cancel != nil {
		ad.cancel()
	}
	close(ad.anomalyChan)
	ad.logger.Info("Anomaly detector stopped")
}

// AddDataPoint adds a new data point and checks for anomalies
func (ad *AnomalyDetector) AddDataPoint(metric string, value float64, labels map[string]string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	dataPoint := DataPoint{
		Metric:    metric,
		Value:     value,
		Timestamp: time.Now(),
		Labels:    labels,
	}
	
	// Add to window
	if ad.dataWindow[metric] == nil {
		ad.dataWindow[metric] = make([]DataPoint, 0)
	}
	ad.dataWindow[metric] = append(ad.dataWindow[metric], dataPoint)
	
	// Clean old data points
	cutoff := time.Now().Add(-ad.config.WindowSize)
	var cleaned []DataPoint
	for _, dp := range ad.dataWindow[metric] {
		if dp.Timestamp.After(cutoff) {
			cleaned = append(cleaned, dp)
		}
	}
	ad.dataWindow[metric] = cleaned
	
	// Check for anomaly if we have enough data points
	if len(ad.dataWindow[metric]) >= ad.config.MinDataPoints {
		if anomaly := ad.detectAnomaly(metric, value, ad.dataWindow[metric]); anomaly != nil {
			select {
			case ad.anomalyChan <- *anomaly:
				ad.logger.WithFields(logrus.Fields{
					"metric":    anomaly.Metric,
					"value":     anomaly.Value,
					"expected":  anomaly.Expected,
					"deviation": anomaly.Deviation,
					"severity":  anomaly.Severity,
				}).Warn("Anomaly detected")
			default:
				// Channel full, drop anomaly
				ad.logger.Warn("Anomaly channel full, dropping anomaly")
			}
		}
	}
}

// detectAnomaly detects if a value is anomalous
func (ad *AnomalyDetector) detectAnomaly(metric string, value float64, window []DataPoint) *Anomaly {
	if len(window) < ad.config.MinDataPoints {
		return nil
	}
	
	// Calculate baseline (moving average)
	sum := 0.0
	for _, dp := range window {
		sum += dp.Value
	}
	baseline := sum / float64(len(window))
	ad.baselines[metric] = baseline
	
	// Calculate standard deviation
	variance := 0.0
	for _, dp := range window {
		diff := dp.Value - baseline
		variance += diff * diff
	}
	stdDev := variance / float64(len(window))
	if stdDev < 0.1 {
		stdDev = 0.1 // Minimum threshold
	}
	
	// Check if current value is anomalous
	deviation := abs(value - baseline)
	threshold := ad.config.ThresholdFactor * stdDev
	
	if deviation > threshold {
		severity := ad.calculateSeverity(deviation, threshold)
		return &Anomaly{
			Metric:    metric,
			Value:     value,
			Expected:  baseline,
			Deviation: deviation,
			Severity:  severity,
			Timestamp: time.Now(),
		}
	}
	
	return nil
}

// calculateSeverity determines the severity of an anomaly
func (ad *AnomalyDetector) calculateSeverity(deviation, threshold float64) AnomalySeverity {
	ratio := deviation / threshold
	
	if ratio > 5.0 {
		return AnomalySeverityCritical
	} else if ratio > 3.0 {
		return AnomalySeverityHigh
	} else if ratio > 2.0 {
		return AnomalySeverityMedium
	} else {
		return AnomalySeverityLow
	}
}

// GetAnomalies returns a channel to receive anomalies
func (ad *AnomalyDetector) GetAnomalies() <-chan Anomaly {
	return ad.anomalyChan
}

// cleanupRoutine periodically cleans up old data
func (ad *AnomalyDetector) cleanupRoutine() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ad.cleanup()
		case <-ad.ctx.Done():
			return
		}
	}
}

// cleanup removes old data points
func (ad *AnomalyDetector) cleanup() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	
	cutoff := time.Now().Add(-ad.config.WindowSize * 2) // Keep 2x window for safety
	
	for metric, window := range ad.dataWindow {
		var cleaned []DataPoint
		for _, dp := range window {
			if dp.Timestamp.After(cutoff) {
				cleaned = append(cleaned, dp)
			}
		}
		ad.dataWindow[metric] = cleaned
	}
}

// abs returns the absolute value of a float64
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}