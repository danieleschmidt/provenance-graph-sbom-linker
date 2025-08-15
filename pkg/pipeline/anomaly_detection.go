package pipeline

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AnomalyDetector implements intelligent anomaly detection for pipeline monitoring
type AnomalyDetector struct {
	config       AnomalyDetectionConfig
	metricBuffers map[string]*MetricBuffer
	anomalies    []Anomaly
	baselines    map[string]*BaselineModel
	logger       *logrus.Logger
	mutex        sync.RWMutex
	running      bool
	stopCh       chan struct{}
}

// AnomalyDetectionConfig defines configuration for anomaly detection
type AnomalyDetectionConfig struct {
	Enabled                 bool          `json:"enabled"`
	WindowSize              int           `json:"window_size"`              // Number of data points to keep
	DetectionInterval       time.Duration `json:"detection_interval"`       // How often to run detection
	Sensitivity             float64       `json:"sensitivity"`              // Anomaly detection sensitivity (0.0-1.0)
	MinDataPoints           int           `json:"min_data_points"`          // Minimum points needed for detection
	BaselineUpdateInterval  time.Duration `json:"baseline_update_interval"`  // How often to update baselines
	SeasonalityDetection    bool          `json:"seasonality_detection"`    // Enable seasonality detection
	SeasonalWindow          time.Duration `json:"seasonal_window"`          // Time window for seasonality (e.g., 24h, 7d)
	AdaptiveThresholds      bool          `json:"adaptive_thresholds"`      // Use adaptive thresholds
	ZScoreThreshold         float64       `json:"z_score_threshold"`        // Z-score threshold for anomaly detection
	PercentileThreshold     float64       `json:"percentile_threshold"`     // Percentile threshold (e.g., 95th percentile)
	ExponentialSmoothingAlpha float64     `json:"exponential_smoothing_alpha"` // Alpha for exponential smoothing
}

// DefaultAnomalyDetectionConfig returns sensible defaults
func DefaultAnomalyDetectionConfig() AnomalyDetectionConfig {
	return AnomalyDetectionConfig{
		Enabled:                   true,
		WindowSize:               100,
		DetectionInterval:         30 * time.Second,
		Sensitivity:               0.8,
		MinDataPoints:             10,
		BaselineUpdateInterval:    5 * time.Minute,
		SeasonalityDetection:      true,
		SeasonalWindow:            24 * time.Hour,
		AdaptiveThresholds:        true,
		ZScoreThreshold:           2.5,
		PercentileThreshold:       95.0,
		ExponentialSmoothingAlpha: 0.3,
	}
}

// MetricBuffer stores time-series data for a specific metric
type MetricBuffer struct {
	MetricName string
	DataPoints []DataPoint
	MaxSize    int
	mutex      sync.RWMutex
}

// DataPoint represents a single metric measurement
type DataPoint struct {
	Value     float64   `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// BaselineModel stores statistical models for normal behavior
type BaselineModel struct {
	MetricName      string            `json:"metric_name"`
	Mean            float64           `json:"mean"`
	StdDev          float64           `json:"std_dev"`
	Min             float64           `json:"min"`
	Max             float64           `json:"max"`
	Percentiles     map[int]float64   `json:"percentiles"`
	Trend           float64           `json:"trend"`
	SeasonalPattern map[int]float64   `json:"seasonal_pattern,omitempty"`
	LastUpdated     time.Time         `json:"last_updated"`
	DataPointCount  int               `json:"data_point_count"`
	EWMA            float64           `json:"ewma"` // Exponentially Weighted Moving Average
	EWMVar          float64           `json:"ewm_var"` // Exponentially Weighted Moving Variance
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID               string                 `json:"id"`
	MetricName       string                 `json:"metric_name"`
	Value            float64                `json:"value"`
	ExpectedValue    float64                `json:"expected_value"`
	DeviationScore   float64                `json:"deviation_score"`
	Severity         AnomalySeverity        `json:"severity"`
	Type             AnomalyType            `json:"type"`
	Timestamp        time.Time              `json:"timestamp"`
	Description      string                 `json:"description"`
	Context          map[string]interface{} `json:"context"`
	Resolved         bool                   `json:"resolved"`
	ResolvedAt       *time.Time             `json:"resolved_at,omitempty"`
	ConfidenceScore  float64                `json:"confidence_score"`
}

// AnomalySeverity defines the severity levels of anomalies
type AnomalySeverity string

const (
	AnomalySeverityLow      AnomalySeverity = "low"
	AnomalySeverityMedium   AnomalySeverity = "medium"
	AnomalySeverityHigh     AnomalySeverity = "high"
	AnomalySeverityCritical AnomalySeverity = "critical"
)

// AnomalyType defines different types of anomalies
type AnomalyType string

const (
	AnomalyTypeSpike          AnomalyType = "spike"
	AnomalyTypeDrop           AnomalyType = "drop"
	AnomalyTypeTrend          AnomalyType = "trend"
	AnomalyTypeSeasonal       AnomalyType = "seasonal"
	AnomalyTypeLevel          AnomalyType = "level"
	AnomalyTypePattern        AnomalyType = "pattern"
	AnomalyTypeFluctuation    AnomalyType = "fluctuation"
)

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config AnomalyDetectionConfig, logger *logrus.Logger) *AnomalyDetector {
	return &AnomalyDetector{
		config:        config,
		metricBuffers: make(map[string]*MetricBuffer),
		anomalies:     make([]Anomaly, 0),
		baselines:     make(map[string]*BaselineModel),
		logger:        logger,
		stopCh:        make(chan struct{}),
	}
}

// Start starts the anomaly detection engine
func (ad *AnomalyDetector) Start(ctx context.Context) error {
	if !ad.config.Enabled {
		return nil
	}
	
	ad.mutex.Lock()
	if ad.running {
		ad.mutex.Unlock()
		return fmt.Errorf("anomaly detector is already running")
	}
	ad.running = true
	ad.mutex.Unlock()
	
	ad.logger.Info("Starting anomaly detection engine")
	
	// Start detection loop
	go ad.detectionLoop(ctx)
	
	// Start baseline update loop
	go ad.baselineUpdateLoop(ctx)
	
	return nil
}

// Stop stops the anomaly detection engine
func (ad *AnomalyDetector) Stop() error {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	if !ad.running {
		return nil
	}
	
	ad.running = false
	close(ad.stopCh)
	
	ad.logger.Info("Stopped anomaly detection engine")
	return nil
}

// AddDataPoint adds a new data point for analysis
func (ad *AnomalyDetector) AddDataPoint(metricName string, value float64, labels map[string]string) {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	// Get or create metric buffer
	buffer, exists := ad.metricBuffers[metricName]
	if !exists {
		buffer = &MetricBuffer{
			MetricName: metricName,
			DataPoints: make([]DataPoint, 0, ad.config.WindowSize),
			MaxSize:    ad.config.WindowSize,
		}
		ad.metricBuffers[metricName] = buffer
	}
	
	// Add data point to buffer
	buffer.AddDataPoint(DataPoint{
		Value:     value,
		Timestamp: time.Now(),
		Labels:    labels,
	})
}

// AddDataPoint adds a data point to the metric buffer
func (mb *MetricBuffer) AddDataPoint(point DataPoint) {
	mb.mutex.Lock()
	defer mb.mutex.Unlock()
	
	mb.DataPoints = append(mb.DataPoints, point)
	
	// Keep only the most recent data points
	if len(mb.DataPoints) > mb.MaxSize {
		mb.DataPoints = mb.DataPoints[1:]
	}
}

// GetDataPoints returns a copy of the data points
func (mb *MetricBuffer) GetDataPoints() []DataPoint {
	mb.mutex.RLock()
	defer mb.mutex.RUnlock()
	
	points := make([]DataPoint, len(mb.DataPoints))
	copy(points, mb.DataPoints)
	return points
}

// detectionLoop runs the main anomaly detection loop
func (ad *AnomalyDetector) detectionLoop(ctx context.Context) {
	ticker := time.NewTicker(ad.config.DetectionInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ad.runAnomalyDetection()
		case <-ad.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// baselineUpdateLoop updates baselines periodically
func (ad *AnomalyDetector) baselineUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(ad.config.BaselineUpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ad.updateBaselines()
		case <-ad.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// runAnomalyDetection runs anomaly detection on all metrics
func (ad *AnomalyDetector) runAnomalyDetection() {
	ad.mutex.RLock()
	metrics := make(map[string]*MetricBuffer)
	for name, buffer := range ad.metricBuffers {
		metrics[name] = buffer
	}
	ad.mutex.RUnlock()
	
	for metricName, buffer := range metrics {
		ad.detectAnomaliesForMetric(metricName, buffer)
	}
}

// detectAnomaliesForMetric detects anomalies for a specific metric
func (ad *AnomalyDetector) detectAnomaliesForMetric(metricName string, buffer *MetricBuffer) {
	dataPoints := buffer.GetDataPoints()
	
	if len(dataPoints) < ad.config.MinDataPoints {
		return
	}
	
	// Get baseline model
	baseline := ad.getOrCreateBaseline(metricName, dataPoints)
	
	// Check the most recent data point
	recentPoint := dataPoints[len(dataPoints)-1]
	anomalies := ad.analyzeDataPoint(metricName, recentPoint, baseline, dataPoints)
	
	// Add detected anomalies
	for _, anomaly := range anomalies {
		ad.addAnomaly(anomaly)
	}
}

// getOrCreateBaseline gets or creates a baseline model for a metric
func (ad *AnomalyDetector) getOrCreateBaseline(metricName string, dataPoints []DataPoint) *BaselineModel {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	baseline, exists := ad.baselines[metricName]
	if !exists {
		baseline = ad.createBaselineModel(metricName, dataPoints)
		ad.baselines[metricName] = baseline
	}
	
	return baseline
}

// createBaselineModel creates a new baseline model from data points
func (ad *AnomalyDetector) createBaselineModel(metricName string, dataPoints []DataPoint) *BaselineModel {
	values := make([]float64, len(dataPoints))
	for i, point := range dataPoints {
		values[i] = point.Value
	}
	
	mean, stdDev := ad.calculateMeanAndStdDev(values)
	percentiles := ad.calculatePercentiles(values)
	trend := ad.calculateTrend(dataPoints)
	
	// Initialize EWMA with the mean
	ewma := mean
	ewmVar := stdDev * stdDev
	
	baseline := &BaselineModel{
		MetricName:     metricName,
		Mean:           mean,
		StdDev:         stdDev,
		Min:            ad.findMin(values),
		Max:            ad.findMax(values),
		Percentiles:    percentiles,
		Trend:          trend,
		LastUpdated:    time.Now(),
		DataPointCount: len(dataPoints),
		EWMA:           ewma,
		EWMVar:         ewmVar,
	}
	
	// Add seasonal pattern if enabled
	if ad.config.SeasonalityDetection {
		baseline.SeasonalPattern = ad.detectSeasonalPattern(dataPoints)
	}
	
	return baseline
}

// updateBaselines updates all baseline models
func (ad *AnomalyDetector) updateBaselines() {
	ad.mutex.RLock()
	metrics := make(map[string]*MetricBuffer)
	for name, buffer := range ad.metricBuffers {
		metrics[name] = buffer
	}
	ad.mutex.RUnlock()
	
	for metricName, buffer := range metrics {
		dataPoints := buffer.GetDataPoints()
		if len(dataPoints) >= ad.config.MinDataPoints {
			ad.updateBaselineModel(metricName, dataPoints)
		}
	}
}

// updateBaselineModel updates a specific baseline model
func (ad *AnomalyDetector) updateBaselineModel(metricName string, dataPoints []DataPoint) {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	baseline, exists := ad.baselines[metricName]
	if !exists {
		return
	}
	
	// Update with exponential smoothing
	recentPoint := dataPoints[len(dataPoints)-1]
	alpha := ad.config.ExponentialSmoothingAlpha
	
	// Update EWMA
	baseline.EWMA = alpha*recentPoint.Value + (1-alpha)*baseline.EWMA
	
	// Update EWMV (Exponentially Weighted Moving Variance)
	diff := recentPoint.Value - baseline.EWMA
	baseline.EWMVar = alpha*diff*diff + (1-alpha)*baseline.EWMVar
	
	// Recalculate full statistics periodically
	if time.Since(baseline.LastUpdated) > ad.config.BaselineUpdateInterval*5 {
		values := make([]float64, len(dataPoints))
		for i, point := range dataPoints {
			values[i] = point.Value
		}
		
		baseline.Mean, baseline.StdDev = ad.calculateMeanAndStdDev(values)
		baseline.Percentiles = ad.calculatePercentiles(values)
		baseline.Trend = ad.calculateTrend(dataPoints)
		baseline.Min = ad.findMin(values)
		baseline.Max = ad.findMax(values)
		
		if ad.config.SeasonalityDetection {
			baseline.SeasonalPattern = ad.detectSeasonalPattern(dataPoints)
		}
	}
	
	baseline.LastUpdated = time.Now()
	baseline.DataPointCount = len(dataPoints)
}

// analyzeDataPoint analyzes a single data point for anomalies
func (ad *AnomalyDetector) analyzeDataPoint(metricName string, point DataPoint, baseline *BaselineModel, history []DataPoint) []Anomaly {
	anomalies := make([]Anomaly, 0)
	
	// Z-score based detection
	zScore := ad.calculateZScore(point.Value, baseline)
	if math.Abs(zScore) > ad.config.ZScoreThreshold {
		anomalyType := AnomalyTypeSpike
		if zScore < 0 {
			anomalyType = AnomalyTypeDrop
		}
		
		anomaly := Anomaly{
			ID:               fmt.Sprintf("%s_%d", metricName, time.Now().UnixNano()),
			MetricName:       metricName,
			Value:            point.Value,
			ExpectedValue:    baseline.EWMA,
			DeviationScore:   math.Abs(zScore),
			Severity:         ad.calculateSeverity(math.Abs(zScore)),
			Type:             anomalyType,
			Timestamp:        point.Timestamp,
			Description:      fmt.Sprintf("Z-score %.2f exceeds threshold %.2f", zScore, ad.config.ZScoreThreshold),
			ConfidenceScore:  ad.calculateConfidence(math.Abs(zScore), baseline),
			Context: map[string]interface{}{
				"z_score":        zScore,
				"baseline_mean":  baseline.Mean,
				"baseline_stddev": baseline.StdDev,
				"detection_method": "z_score",
			},
		}
		
		anomalies = append(anomalies, anomaly)
	}
	
	// Percentile-based detection
	if ad.config.AdaptiveThresholds {
		percentileAnomalies := ad.detectPercentileAnomalies(metricName, point, baseline)
		anomalies = append(anomalies, percentileAnomalies...)
	}
	
	// Trend-based detection
	trendAnomalies := ad.detectTrendAnomalies(metricName, point, baseline, history)
	anomalies = append(anomalies, trendAnomalies...)
	
	// Seasonal anomaly detection
	if ad.config.SeasonalityDetection && baseline.SeasonalPattern != nil {
		seasonalAnomalies := ad.detectSeasonalAnomalies(metricName, point, baseline)
		anomalies = append(anomalies, seasonalAnomalies...)
	}
	
	return anomalies
}

// detectPercentileAnomalies detects anomalies using percentile thresholds
func (ad *AnomalyDetector) detectPercentileAnomalies(metricName string, point DataPoint, baseline *BaselineModel) []Anomaly {
	anomalies := make([]Anomaly, 0)
	
	if baseline.Percentiles == nil {
		return anomalies
	}
	
	threshold := ad.config.PercentileThreshold
	highThreshold, highExists := baseline.Percentiles[int(threshold)]
	lowThreshold, lowExists := baseline.Percentiles[int(100-threshold)]
	
	if highExists && point.Value > highThreshold {
		anomaly := Anomaly{
			ID:              fmt.Sprintf("%s_percentile_%d", metricName, time.Now().UnixNano()),
			MetricName:      metricName,
			Value:           point.Value,
			ExpectedValue:   baseline.Mean,
			DeviationScore:  (point.Value - highThreshold) / (baseline.Max - baseline.Mean),
			Severity:        ad.calculateSeverityFromPercentile(point.Value, highThreshold, baseline),
			Type:            AnomalyTypeSpike,
			Timestamp:       point.Timestamp,
			Description:     fmt.Sprintf("Value %.2f exceeds %.0f percentile threshold %.2f", point.Value, threshold, highThreshold),
			ConfidenceScore: 0.8,
			Context: map[string]interface{}{
				"percentile":         threshold,
				"threshold":          highThreshold,
				"detection_method":   "percentile",
			},
		}
		anomalies = append(anomalies, anomaly)
	}
	
	if lowExists && point.Value < lowThreshold {
		anomaly := Anomaly{
			ID:              fmt.Sprintf("%s_percentile_low_%d", metricName, time.Now().UnixNano()),
			MetricName:      metricName,
			Value:           point.Value,
			ExpectedValue:   baseline.Mean,
			DeviationScore:  (lowThreshold - point.Value) / (baseline.Mean - baseline.Min),
			Severity:        ad.calculateSeverityFromPercentile(point.Value, lowThreshold, baseline),
			Type:            AnomalyTypeDrop,
			Timestamp:       point.Timestamp,
			Description:     fmt.Sprintf("Value %.2f below %.0f percentile threshold %.2f", point.Value, 100-threshold, lowThreshold),
			ConfidenceScore: 0.8,
			Context: map[string]interface{}{
				"percentile":        100 - threshold,
				"threshold":         lowThreshold,
				"detection_method":  "percentile",
			},
		}
		anomalies = append(anomalies, anomaly)
	}
	
	return anomalies
}

// detectTrendAnomalies detects trend-based anomalies
func (ad *AnomalyDetector) detectTrendAnomalies(metricName string, point DataPoint, baseline *BaselineModel, history []DataPoint) []Anomaly {
	anomalies := make([]Anomaly, 0)
	
	if len(history) < 10 {
		return anomalies
	}
	
	// Calculate recent trend
	recentTrend := ad.calculateTrend(history[len(history)-10:])
	
	// Compare with baseline trend
	trendDeviation := math.Abs(recentTrend - baseline.Trend)
	
	// If trend deviation is significant
	if trendDeviation > 0.1 && math.Abs(recentTrend) > 0.05 {
		anomaly := Anomaly{
			ID:              fmt.Sprintf("%s_trend_%d", metricName, time.Now().UnixNano()),
			MetricName:      metricName,
			Value:           point.Value,
			ExpectedValue:   baseline.Mean,
			DeviationScore:  trendDeviation,
			Severity:        ad.calculateSeverityFromTrend(trendDeviation),
			Type:            AnomalyTypeTrend,
			Timestamp:       point.Timestamp,
			Description:     fmt.Sprintf("Unusual trend detected: %.4f vs baseline %.4f", recentTrend, baseline.Trend),
			ConfidenceScore: 0.7,
			Context: map[string]interface{}{
				"recent_trend":      recentTrend,
				"baseline_trend":    baseline.Trend,
				"trend_deviation":   trendDeviation,
				"detection_method":  "trend",
			},
		}
		anomalies = append(anomalies, anomaly)
	}
	
	return anomalies
}

// detectSeasonalAnomalies detects seasonal pattern anomalies
func (ad *AnomalyDetector) detectSeasonalAnomalies(metricName string, point DataPoint, baseline *BaselineModel) []Anomaly {
	anomalies := make([]Anomaly, 0)
	
	if baseline.SeasonalPattern == nil {
		return anomalies
	}
	
	// Get expected seasonal value
	hour := point.Timestamp.Hour()
	expectedSeasonal, exists := baseline.SeasonalPattern[hour]
	
	if exists {
		seasonalDeviation := math.Abs(point.Value - expectedSeasonal)
		seasonalThreshold := baseline.StdDev * 1.5 // Adjustable threshold
		
		if seasonalDeviation > seasonalThreshold {
			anomaly := Anomaly{
				ID:              fmt.Sprintf("%s_seasonal_%d", metricName, time.Now().UnixNano()),
				MetricName:      metricName,
				Value:           point.Value,
				ExpectedValue:   expectedSeasonal,
				DeviationScore:  seasonalDeviation / seasonalThreshold,
				Severity:        ad.calculateSeverityFromDeviation(seasonalDeviation, seasonalThreshold),
				Type:            AnomalySeasonal,
				Timestamp:       point.Timestamp,
				Description:     fmt.Sprintf("Seasonal anomaly: %.2f vs expected %.2f for hour %d", point.Value, expectedSeasonal, hour),
				ConfidenceScore: 0.75,
				Context: map[string]interface{}{
					"hour":               hour,
					"expected_seasonal":  expectedSeasonal,
					"seasonal_deviation": seasonalDeviation,
					"detection_method":   "seasonal",
				},
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	
	return anomalies
}

// Statistical calculation methods

// calculateMeanAndStdDev calculates mean and standard deviation
func (ad *AnomalyDetector) calculateMeanAndStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	
	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	
	// Calculate standard deviation
	sumSquaredDiff := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquaredDiff += diff * diff
	}
	variance := sumSquaredDiff / float64(len(values))
	stdDev := math.Sqrt(variance)
	
	return mean, stdDev
}

// calculatePercentiles calculates various percentiles
func (ad *AnomalyDetector) calculatePercentiles(values []float64) map[int]float64 {
	if len(values) == 0 {
		return nil
	}
	
	// Sort values
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	
	percentiles := make(map[int]float64)
	percentilesToCalculate := []int{5, 10, 25, 50, 75, 90, 95, 99}
	
	for _, p := range percentilesToCalculate {
		index := float64(p) / 100.0 * float64(len(sorted)-1)
		lower := int(math.Floor(index))
		upper := int(math.Ceil(index))
		
		if lower == upper {
			percentiles[p] = sorted[lower]
		} else {
			weight := index - float64(lower)
			percentiles[p] = sorted[lower]*(1-weight) + sorted[upper]*weight
		}
	}
	
	return percentiles
}

// calculateTrend calculates the trend (slope) of data points
func (ad *AnomalyDetector) calculateTrend(dataPoints []DataPoint) float64 {
	if len(dataPoints) < 2 {
		return 0
	}
	
	n := float64(len(dataPoints))
	sumX := 0.0
	sumY := 0.0
	sumXY := 0.0
	sumX2 := 0.0
	
	// Use time index as X, value as Y
	for i, point := range dataPoints {
		x := float64(i)
		y := point.Value
		
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}
	
	// Calculate slope using least squares
	numerator := n*sumXY - sumX*sumY
	denominator := n*sumX2 - sumX*sumX
	
	if denominator == 0 {
		return 0
	}
	
	return numerator / denominator
}

// findMin finds the minimum value in a slice
func (ad *AnomalyDetector) findMin(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

// findMax finds the maximum value in a slice
func (ad *AnomalyDetector) findMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

// calculateZScore calculates the Z-score for a value
func (ad *AnomalyDetector) calculateZScore(value float64, baseline *BaselineModel) float64 {
	if baseline.StdDev == 0 {
		return 0
	}
	
	// Use EWMA and EWMV for more responsive detection
	ewmaStdDev := math.Sqrt(baseline.EWMVar)
	if ewmaStdDev == 0 {
		ewmaStdDev = baseline.StdDev
	}
	
	return (value - baseline.EWMA) / ewmaStdDev
}

// detectSeasonalPattern detects seasonal patterns in data
func (ad *AnomalyDetector) detectSeasonalPattern(dataPoints []DataPoint) map[int]float64 {
	if len(dataPoints) < 24 { // Need at least one day of hourly data
		return nil
	}
	
	hourlyValues := make(map[int][]float64)
	
	// Group values by hour
	for _, point := range dataPoints {
		hour := point.Timestamp.Hour()
		hourlyValues[hour] = append(hourlyValues[hour], point.Value)
	}
	
	// Calculate average for each hour
	seasonalPattern := make(map[int]float64)
	for hour, values := range hourlyValues {
		if len(values) > 0 {
			sum := 0.0
			for _, v := range values {
				sum += v
			}
			seasonalPattern[hour] = sum / float64(len(values))
		}
	}
	
	return seasonalPattern
}

// Severity calculation methods

// calculateSeverity calculates anomaly severity based on Z-score
func (ad *AnomalyDetector) calculateSeverity(zScore float64) AnomalySeverity {
	if zScore >= 4.0 {
		return AnomalySeverityCritical
	} else if zScore >= 3.0 {
		return AnomalySeverityHigh
	} else if zScore >= 2.0 {
		return AnomalySeverityMedium
	} else {
		return AnomalySeverityLow
	}
}

// calculateSeverityFromPercentile calculates severity based on percentile deviation
func (ad *AnomalyDetector) calculateSeverityFromPercentile(value, threshold float64, baseline *BaselineModel) AnomalySeverity {
	deviationRatio := math.Abs(value-threshold) / (baseline.Max - baseline.Min)
	
	if deviationRatio >= 0.5 {
		return AnomalySeverityCritical
	} else if deviationRatio >= 0.3 {
		return AnomalySeverityHigh
	} else if deviationRatio >= 0.1 {
		return AnomalySeverityMedium
	} else {
		return AnomalySeverityLow
	}
}

// calculateSeverityFromTrend calculates severity based on trend deviation
func (ad *AnomalyDetector) calculateSeverityFromTrend(trendDeviation float64) AnomalySeverity {
	if trendDeviation >= 0.5 {
		return AnomalySeverityCritical
	} else if trendDeviation >= 0.3 {
		return AnomalySeverityHigh
	} else if trendDeviation >= 0.15 {
		return AnomalySeverityMedium
	} else {
		return AnomalySeverityLow
	}
}

// calculateSeverityFromDeviation calculates severity based on general deviation
func (ad *AnomalyDetector) calculateSeverityFromDeviation(deviation, threshold float64) AnomalySeverity {
	ratio := deviation / threshold
	
	if ratio >= 3.0 {
		return AnomalySeverityCritical
	} else if ratio >= 2.0 {
		return AnomalySeverityHigh
	} else if ratio >= 1.5 {
		return AnomalySeverityMedium
	} else {
		return AnomalySeverityLow
	}
}

// calculateConfidence calculates confidence score for anomaly detection
func (ad *AnomalyDetector) calculateConfidence(zScore float64, baseline *BaselineModel) float64 {
	// Base confidence on Z-score magnitude and data quality
	confidence := math.Min(zScore/5.0, 1.0) // Scale Z-score to 0-1
	
	// Adjust based on data quality (more data points = higher confidence)
	dataQuality := math.Min(float64(baseline.DataPointCount)/100.0, 1.0)
	confidence *= (0.5 + 0.5*dataQuality)
	
	// Ensure minimum and maximum bounds
	if confidence < 0.1 {
		confidence = 0.1
	}
	if confidence > 0.95 {
		confidence = 0.95
	}
	
	return confidence
}

// Public API methods

// addAnomaly adds an anomaly to the list
func (ad *AnomalyDetector) addAnomaly(anomaly Anomaly) {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	ad.anomalies = append(ad.anomalies, anomaly)
	
	// Keep only recent anomalies (last 1000)
	if len(ad.anomalies) > 1000 {
		ad.anomalies = ad.anomalies[100:] // Remove oldest 100
	}
	
	ad.logger.WithFields(logrus.Fields{
		"anomaly_id":   anomaly.ID,
		"metric_name":  anomaly.MetricName,
		"severity":     anomaly.Severity,
		"type":         anomaly.Type,
		"value":        anomaly.Value,
		"expected":     anomaly.ExpectedValue,
		"confidence":   anomaly.ConfidenceScore,
	}).Warn("Anomaly detected")
}

// GetAnomalies returns recent anomalies
func (ad *AnomalyDetector) GetAnomalies(limit int) []Anomaly {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()
	
	if limit <= 0 || limit > len(ad.anomalies) {
		limit = len(ad.anomalies)
	}
	
	// Return most recent anomalies
	start := len(ad.anomalies) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]Anomaly, limit)
	copy(result, ad.anomalies[start:])
	return result
}

// GetAnomaliesByMetric returns anomalies for a specific metric
func (ad *AnomalyDetector) GetAnomaliesByMetric(metricName string, limit int) []Anomaly {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()
	
	var filtered []Anomaly
	for _, anomaly := range ad.anomalies {
		if anomaly.MetricName == metricName {
			filtered = append(filtered, anomaly)
		}
	}
	
	if limit > 0 && limit < len(filtered) {
		// Return most recent
		start := len(filtered) - limit
		filtered = filtered[start:]
	}
	
	return filtered
}

// GetBaselines returns current baseline models
func (ad *AnomalyDetector) GetBaselines() map[string]*BaselineModel {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()
	
	result := make(map[string]*BaselineModel)
	for name, baseline := range ad.baselines {
		// Create a copy
		baselineCopy := *baseline
		result[name] = &baselineCopy
	}
	return result
}

// ResolveAnomaly marks an anomaly as resolved
func (ad *AnomalyDetector) ResolveAnomaly(anomalyID string) error {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()
	
	for i := range ad.anomalies {
		if ad.anomalies[i].ID == anomalyID {
			now := time.Now()
			ad.anomalies[i].Resolved = true
			ad.anomalies[i].ResolvedAt = &now
			
			ad.logger.WithField("anomaly_id", anomalyID).Info("Anomaly resolved")
			return nil
		}
	}
	
	return fmt.Errorf("anomaly with ID %s not found", anomalyID)
}

// GetAnomalyStats returns statistics about detected anomalies
func (ad *AnomalyDetector) GetAnomalyStats() map[string]interface{} {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()
	
	totalAnomalies := len(ad.anomalies)
	resolvedCount := 0
	severityCounts := make(map[AnomalySeverity]int)
	typeCounts := make(map[AnomalyType]int)
	
	for _, anomaly := range ad.anomalies {
		if anomaly.Resolved {
			resolvedCount++
		}
		severityCounts[anomaly.Severity]++
		typeCounts[anomaly.Type]++
	}
	
	return map[string]interface{}{
		"total_anomalies":   totalAnomalies,
		"resolved_count":    resolvedCount,
		"unresolved_count":  totalAnomalies - resolvedCount,
		"severity_counts":   severityCounts,
		"type_counts":       typeCounts,
		"detection_enabled": ad.config.Enabled,
		"metrics_monitored": len(ad.metricBuffers),
	}
}
