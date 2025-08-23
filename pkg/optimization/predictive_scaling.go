package optimization

import (
	"math"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

// PredictiveScaler uses machine learning techniques to predict and scale resources
type PredictiveScaler struct {
	logger           *logrus.Logger
	metricsCollector *monitoring.MetricsCollector
	
	// Historical data for predictions
	cpuHistory       []DataPoint
	memoryHistory    []DataPoint
	requestHistory   []DataPoint
	
	// Prediction models
	cpuPredictor     *LinearRegression
	memoryPredictor  *LinearRegression
	requestPredictor *LinearRegression
	
	// Configuration
	windowSize       int
	predictionWindow time.Duration
	scalingThreshold float64
	
	mu sync.RWMutex
}

// DataPoint represents a time-series data point
type DataPoint struct {
	Timestamp time.Time
	Value     float64
}

// PredictionResult contains scaling predictions
type PredictionResult struct {
	CPUPrediction     float64   `json:"cpu_prediction"`
	MemoryPrediction  float64   `json:"memory_prediction"`
	RequestPrediction float64   `json:"request_prediction"`
	ScaleRecommendation string  `json:"scale_recommendation"`
	Confidence        float64   `json:"confidence"`
	PredictedFor      time.Time `json:"predicted_for"`
}

// NewPredictiveScaler creates a new predictive scaler
func NewPredictiveScaler(logger *logrus.Logger, metricsCollector *monitoring.MetricsCollector) *PredictiveScaler {
	return &PredictiveScaler{
		logger:           logger,
		metricsCollector: metricsCollector,
		windowSize:       100,
		predictionWindow: 10 * time.Minute,
		scalingThreshold: 0.75,
		cpuPredictor:     NewLinearRegression(),
		memoryPredictor:  NewLinearRegression(),
		requestPredictor: NewLinearRegression(),
	}
}

// CollectMetrics collects and stores metrics for prediction
func (ps *PredictiveScaler) CollectMetrics() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	
	metrics := ps.metricsCollector.GetApplicationMetrics()
	now := time.Now()
	
	// Add new data points
	ps.cpuHistory = append(ps.cpuHistory, DataPoint{
		Timestamp: now,
		Value:     metrics.CPUUsagePercent,
	})
	
	ps.memoryHistory = append(ps.memoryHistory, DataPoint{
		Timestamp: now,
		Value:     metrics.MemoryUsageMB,
	})
	
	ps.requestHistory = append(ps.requestHistory, DataPoint{
		Timestamp: now,
		Value:     metrics.RequestsPerSecond,
	})
	
	// Maintain window size
	if len(ps.cpuHistory) > ps.windowSize {
		ps.cpuHistory = ps.cpuHistory[1:]
	}
	if len(ps.memoryHistory) > ps.windowSize {
		ps.memoryHistory = ps.memoryHistory[1:]
	}
	if len(ps.requestHistory) > ps.windowSize {
		ps.requestHistory = ps.requestHistory[1:]
	}
	
	// Update prediction models
	ps.updateModels()
}

// updateModels updates the prediction models with recent data
func (ps *PredictiveScaler) updateModels() {
	// Update CPU predictor
	if len(ps.cpuHistory) >= 10 {
		ps.cpuPredictor.Train(ps.prepareTrainingData(ps.cpuHistory))
	}
	
	// Update memory predictor
	if len(ps.memoryHistory) >= 10 {
		ps.memoryPredictor.Train(ps.prepareTrainingData(ps.memoryHistory))
	}
	
	// Update request predictor
	if len(ps.requestHistory) >= 10 {
		ps.requestPredictor.Train(ps.prepareTrainingData(ps.requestHistory))
	}
}

// prepareTrainingData converts time series data to training format
func (ps *PredictiveScaler) prepareTrainingData(history []DataPoint) ([]float64, []float64) {
	if len(history) < 2 {
		return nil, nil
	}
	
	x := make([]float64, len(history))
	y := make([]float64, len(history))
	
	baseTime := history[0].Timestamp
	for i, point := range history {
		x[i] = float64(point.Timestamp.Sub(baseTime).Minutes())
		y[i] = point.Value
	}
	
	return x, y
}

// Predict generates scaling predictions
func (ps *PredictiveScaler) Predict() *PredictionResult {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	
	if len(ps.cpuHistory) < 10 {
		return &PredictionResult{
			ScaleRecommendation: "insufficient_data",
			Confidence:          0.0,
			PredictedFor:        time.Now().Add(ps.predictionWindow),
		}
	}
	
	// Calculate prediction time (minutes from base time)
	baseTime := ps.cpuHistory[0].Timestamp
	predictionTime := time.Now().Add(ps.predictionWindow)
	x := float64(predictionTime.Sub(baseTime).Minutes())
	
	// Generate predictions
	cpuPred := ps.cpuPredictor.Predict(x)
	memoryPred := ps.memoryPredictor.Predict(x)
	requestPred := ps.requestPredictor.Predict(x)
	
	// Calculate confidence based on model accuracy
	confidence := ps.calculateConfidence()
	
	// Generate scaling recommendation
	recommendation := ps.generateRecommendation(cpuPred, memoryPred, requestPred)
	
	result := &PredictionResult{
		CPUPrediction:     cpuPred,
		MemoryPrediction:  memoryPred,
		RequestPrediction: requestPred,
		ScaleRecommendation: recommendation,
		Confidence:        confidence,
		PredictedFor:      predictionTime,
	}
	
	ps.logger.WithFields(logrus.Fields{
		"cpu_prediction":     cpuPred,
		"memory_prediction":  memoryPred,
		"request_prediction": requestPred,
		"recommendation":     recommendation,
		"confidence":         confidence,
	}).Debug("Generated scaling prediction")
	
	return result
}

// calculateConfidence calculates prediction confidence based on model accuracy
func (ps *PredictiveScaler) calculateConfidence() float64 {
	// Simple confidence calculation based on data availability and trend stability
	dataQuality := float64(len(ps.cpuHistory)) / float64(ps.windowSize)
	
	// Calculate trend stability (lower variance = higher confidence)
	cpuVariance := ps.calculateVariance(ps.cpuHistory)
	memoryVariance := ps.calculateVariance(ps.memoryHistory)
	
	// Normalize variances and convert to confidence
	stabilityScore := 1.0 / (1.0 + (cpuVariance+memoryVariance)/200)
	
	// Combined confidence score
	confidence := (dataQuality + stabilityScore) / 2.0
	
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	
	return confidence
}

// calculateVariance calculates variance in data points
func (ps *PredictiveScaler) calculateVariance(data []DataPoint) float64 {
	if len(data) < 2 {
		return 0.0
	}
	
	// Calculate mean
	sum := 0.0
	for _, point := range data {
		sum += point.Value
	}
	mean := sum / float64(len(data))
	
	// Calculate variance
	sumSquaredDiffs := 0.0
	for _, point := range data {
		diff := point.Value - mean
		sumSquaredDiffs += diff * diff
	}
	
	return sumSquaredDiffs / float64(len(data)-1)
}

// generateRecommendation generates scaling recommendations based on predictions
func (ps *PredictiveScaler) generateRecommendation(cpuPred, memoryPred, requestPred float64) string {
	// Define thresholds for scaling decisions
	highCPUThreshold := 75.0
	highMemoryThreshold := 80.0
	lowCPUThreshold := 25.0
	lowMemoryThreshold := 30.0
	
	// Scale up conditions
	if cpuPred > highCPUThreshold || memoryPred > highMemoryThreshold {
		if cpuPred > 90.0 || memoryPred > 90.0 {
			return "scale_up_aggressive"
		}
		return "scale_up"
	}
	
	// Scale down conditions
	if cpuPred < lowCPUThreshold && memoryPred < lowMemoryThreshold {
		return "scale_down"
	}
	
	// Maintain current scale
	return "maintain"
}

// GetHistoricalData returns historical metrics data
func (ps *PredictiveScaler) GetHistoricalData() map[string][]DataPoint {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	
	return map[string][]DataPoint{
		"cpu":      append([]DataPoint{}, ps.cpuHistory...),
		"memory":   append([]DataPoint{}, ps.memoryHistory...),
		"requests": append([]DataPoint{}, ps.requestHistory...),
	}
}

// LinearRegression implements a simple linear regression model
type LinearRegression struct {
	slope     float64
	intercept float64
	trained   bool
	mu        sync.RWMutex
}

// NewLinearRegression creates a new linear regression model
func NewLinearRegression() *LinearRegression {
	return &LinearRegression{}
}

// Train trains the linear regression model
func (lr *LinearRegression) Train(x, y []float64) {
	if len(x) != len(y) || len(x) < 2 {
		return
	}
	
	lr.mu.Lock()
	defer lr.mu.Unlock()
	
	// Calculate slope and intercept using least squares
	n := float64(len(x))
	sumX := 0.0
	sumY := 0.0
	sumXY := 0.0
	sumXX := 0.0
	
	for i := 0; i < len(x); i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumXX += x[i] * x[i]
	}
	
	// Calculate slope and intercept
	denominator := n*sumXX - sumX*sumX
	if math.Abs(denominator) > 1e-10 {
		lr.slope = (n*sumXY - sumX*sumY) / denominator
		lr.intercept = (sumY - lr.slope*sumX) / n
		lr.trained = true
	}
}

// Predict makes a prediction using the trained model
func (lr *LinearRegression) Predict(x float64) float64 {
	lr.mu.RLock()
	defer lr.mu.RUnlock()
	
	if !lr.trained {
		return 0.0
	}
	
	return lr.slope*x + lr.intercept
}

// IsTrained returns whether the model has been trained
func (lr *LinearRegression) IsTrained() bool {
	lr.mu.RLock()
	defer lr.mu.RUnlock()
	return lr.trained
}

// SeasonalityDetector detects seasonal patterns in metrics
type SeasonalityDetector struct {
	data      []DataPoint
	period    time.Duration
	threshold float64
}

// NewSeasonalityDetector creates a new seasonality detector
func NewSeasonalityDetector(period time.Duration) *SeasonalityDetector {
	return &SeasonalityDetector{
		period:    period,
		threshold: 0.3, // Minimum correlation for seasonality detection
	}
}

// DetectSeasonality detects seasonal patterns in the data
func (sd *SeasonalityDetector) DetectSeasonality(data []DataPoint) bool {
	if len(data) < int(sd.period.Minutes()) {
		return false
	}
	
	// Calculate autocorrelation at seasonal lag
	lag := int(sd.period.Minutes())
	if lag >= len(data) {
		return false
	}
	
	correlation := sd.calculateAutocorrelation(data, lag)
	return math.Abs(correlation) > sd.threshold
}

// calculateAutocorrelation calculates autocorrelation at a given lag
func (sd *SeasonalityDetector) calculateAutocorrelation(data []DataPoint, lag int) float64 {
	if lag >= len(data) || lag <= 0 {
		return 0.0
	}
	
	// Calculate mean
	sum := 0.0
	for _, point := range data {
		sum += point.Value
	}
	mean := sum / float64(len(data))
	
	// Calculate autocorrelation
	numerator := 0.0
	denominator := 0.0
	
	for i := 0; i < len(data)-lag; i++ {
		numerator += (data[i].Value - mean) * (data[i+lag].Value - mean)
	}
	
	for _, point := range data {
		denominator += (point.Value - mean) * (point.Value - mean)
	}
	
	if denominator == 0 {
		return 0.0
	}
	
	return numerator / denominator
}

// TrendAnalyzer analyzes trends in metrics data
type TrendAnalyzer struct {
	windowSize int
}

// NewTrendAnalyzer creates a new trend analyzer
func NewTrendAnalyzer(windowSize int) *TrendAnalyzer {
	return &TrendAnalyzer{windowSize: windowSize}
}

// AnalyzeTrend analyzes the trend in recent data
func (ta *TrendAnalyzer) AnalyzeTrend(data []DataPoint) string {
	if len(data) < ta.windowSize {
		return "insufficient_data"
	}
	
	// Use the most recent data points
	recentData := data[len(data)-ta.windowSize:]
	
	// Calculate trend using linear regression
	x := make([]float64, len(recentData))
	y := make([]float64, len(recentData))
	
	for i, point := range recentData {
		x[i] = float64(i)
		y[i] = point.Value
	}
	
	lr := NewLinearRegression()
	lr.Train(x, y)
	
	if !lr.IsTrained() {
		return "unknown"
	}
	
	// Classify trend based on slope
	slope := lr.slope
	if slope > 0.5 {
		return "increasing"
	} else if slope < -0.5 {
		return "decreasing"
	} else {
		return "stable"
	}
}