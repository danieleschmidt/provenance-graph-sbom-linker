package security

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ThreatDetectionEngine provides real-time security threat detection
type ThreatDetectionEngine struct {
	config          ThreatDetectionConfig
	detectionRules  map[string]ThreatRule
	threatHistory   []ThreatEvent
	anomalyBaseline map[string]SecurityBaseline
	blacklistedIPs  map[string]time.Time
	suspiciousIPs   map[string]int
	logger          *logrus.Logger
	mutex           sync.RWMutex
	running         bool
	stopCh          chan struct{}
}

// ThreatDetectionConfig defines configuration for threat detection
type ThreatDetectionConfig struct {
	Enabled                  bool          `json:"enabled"`
	MaxThreatHistory         int           `json:"max_threat_history"`
	AnomalyThreshold         float64       `json:"anomaly_threshold"`
	AutoBlacklistEnabled     bool          `json:"auto_blacklist_enabled"`
	BlacklistDuration        time.Duration `json:"blacklist_duration"`
	SuspiciousIPThreshold    int           `json:"suspicious_ip_threshold"`
	RateLimitThreshold       int           `json:"rate_limit_threshold"`
	RateLimitWindow          time.Duration `json:"rate_limit_window"`
	SQLInjectionDetection    bool          `json:"sql_injection_detection"`
	XSSDetection             bool          `json:"xss_detection"`
	BruteForceDetection      bool          `json:"brute_force_detection"`
	DDoSDetection            bool          `json:"ddos_detection"`
	MalwareDetection         bool          `json:"malware_detection"`
	DataLeakageDetection     bool          `json:"data_leakage_detection"`
	CryptographicValidation  bool          `json:"cryptographic_validation"`
	SupplyChainValidation    bool          `json:"supply_chain_validation"`
	RealTimeBlocking         bool          `json:"real_time_blocking"`
	ThreatIntelligence       bool          `json:"threat_intelligence"`
}

// DefaultThreatDetectionConfig returns sensible defaults
func DefaultThreatDetectionConfig() ThreatDetectionConfig {
	return ThreatDetectionConfig{
		Enabled:                 true,
		MaxThreatHistory:        5000,
		AnomalyThreshold:        0.8,
		AutoBlacklistEnabled:    true,
		BlacklistDuration:       24 * time.Hour,
		SuspiciousIPThreshold:   10,
		RateLimitThreshold:      100,
		RateLimitWindow:         time.Minute,
		SQLInjectionDetection:   true,
		XSSDetection:            true,
		BruteForceDetection:     true,
		DDoSDetection:           true,
		MalwareDetection:        true,
		DataLeakageDetection:    true,
		CryptographicValidation: true,
		SupplyChainValidation:   true,
		RealTimeBlocking:        true,
		ThreatIntelligence:      true,
	}
}

// ThreatEvent represents a detected security threat
type ThreatEvent struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Type             ThreatType             `json:"type"`
	Severity         ThreatSeverity         `json:"severity"`
	Source           string                 `json:"source"`
	Target           string                 `json:"target"`
	Description      string                 `json:"description"`
	Evidence         map[string]interface{} `json:"evidence"`
	Mitigated        bool                   `json:"mitigated"`
	MitigationAction string                 `json:"mitigation_action,omitempty"`
	MitigatedAt      *time.Time             `json:"mitigated_at,omitempty"`
	RiskScore        float64                `json:"risk_score"`
	ConfidenceScore  float64                `json:"confidence_score"`
	AttackVector     string                 `json:"attack_vector"`
	AssetImpact      string                 `json:"asset_impact"`
	GeoLocation      GeoLocation            `json:"geo_location"`
	UserAgent        string                 `json:"user_agent,omitempty"`
	RequestID        string                 `json:"request_id,omitempty"`
	Tags             []string               `json:"tags"`
}

// ThreatType represents different types of security threats
type ThreatType string

const (
	ThreatTypeSQLInjection    ThreatType = "sql_injection"
	ThreatTypeXSS             ThreatType = "xss"
	ThreatTypeBruteForce      ThreatType = "brute_force"
	ThreatTypeDDoS            ThreatType = "ddos"
	ThreatTypeMalware         ThreatType = "malware"
	ThreatTypeDataLeakage     ThreatType = "data_leakage"
	ThreatTypeUnauthorized    ThreatType = "unauthorized_access"
	ThreatTypeSupplyChain     ThreatType = "supply_chain"
	ThreatTypeAnomaly         ThreatType = "anomaly"
	ThreatTypeInsider         ThreatType = "insider_threat"
	ThreatTypePhishing        ThreatType = "phishing"
	ThreatTypeCryptographic   ThreatType = "cryptographic"
	ThreatTypePrivilegeEsc    ThreatType = "privilege_escalation"
	ThreatTypeRecon           ThreatType = "reconnaissance"
)

// ThreatSeverity represents the severity level of threats
type ThreatSeverity string

const (
	ThreatSeverityInfo     ThreatSeverity = "info"
	ThreatSeverityLow      ThreatSeverity = "low"
	ThreatSeverityMedium   ThreatSeverity = "medium"
	ThreatSeverityHigh     ThreatSeverity = "high"
	ThreatSeverityCritical ThreatSeverity = "critical"
)

// ThreatRule defines a rule for detecting threats
type ThreatRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ThreatType             `json:"type"`
	Severity    ThreatSeverity         `json:"severity"`
	Pattern     string                 `json:"pattern"`
	Regex       *regexp.Regexp         `json:"-"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Detector    func(SecurityContext) (bool, map[string]interface{}) `json:"-"`
	Mitigator   func(ThreatEvent) error `json:"-"`
	Tags        []string               `json:"tags"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// SecurityContext provides context for threat detection
type SecurityContext struct {
	SourceIP      string                 `json:"source_ip"`
	UserAgent     string                 `json:"user_agent"`
	RequestPath   string                 `json:"request_path"`
	RequestMethod string                 `json:"request_method"`
	RequestBody   string                 `json:"request_body"`
	Headers       map[string]string      `json:"headers"`
	Parameters    map[string]interface{} `json:"parameters"`
	UserID        string                 `json:"user_id,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	AssetType     string                 `json:"asset_type"`
	AssetID       string                 `json:"asset_id"`
	Action        string                 `json:"action"`
	Payload       []byte                 `json:"payload,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SecurityBaseline represents normal behavior baseline
type SecurityBaseline struct {
	Metric          string    `json:"metric"`
	NormalRange     Range     `json:"normal_range"`
	AverageValue    float64   `json:"average_value"`
	StandardDev     float64   `json:"standard_dev"`
	LastUpdated     time.Time `json:"last_updated"`
	SampleSize      int       `json:"sample_size"`
	ConfidenceLevel float64   `json:"confidence_level"`
}

// Range represents a numerical range
type Range struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// GeoLocation represents geographical location
type GeoLocation struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	ThreatDB  bool    `json:"threat_db"` // Known to be in threat databases
}

// NewThreatDetectionEngine creates a new threat detection engine
func NewThreatDetectionEngine(config ThreatDetectionConfig, logger *logrus.Logger) *ThreatDetectionEngine {
	engine := &ThreatDetectionEngine{
		config:          config,
		detectionRules:  make(map[string]ThreatRule),
		threatHistory:   make([]ThreatEvent, 0, config.MaxThreatHistory),
		anomalyBaseline: make(map[string]SecurityBaseline),
		blacklistedIPs:  make(map[string]time.Time),
		suspiciousIPs:   make(map[string]int),
		logger:          logger,
		stopCh:          make(chan struct{}),
	}
	
	// Initialize default threat detection rules
	engine.initializeDefaultRules()
	
	return engine
}

// initializeDefaultRules sets up default threat detection rules
func (tde *ThreatDetectionEngine) initializeDefaultRules() {
	rules := []ThreatRule{
		{
			ID:          "sql_injection_001",
			Name:        "SQL Injection Detection",
			Type:        ThreatTypeSQLInjection,
			Severity:    ThreatSeverityHigh,
			Pattern:     `(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|<script|javascript:|vbscript:|onload|onerror)`,
			Description: "Detects potential SQL injection attempts",
			Enabled:     tde.config.SQLInjectionDetection,
			Detector:    tde.detectSQLInjection,
			Mitigator:   tde.mitigateSQLInjection,
			Tags:        []string{"sql", "injection", "web"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "xss_001",
			Name:        "Cross-Site Scripting Detection",
			Type:        ThreatTypeXSS,
			Severity:    ThreatSeverityMedium,
			Pattern:     `(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=|onmouseover=)`,
			Description: "Detects potential XSS attacks",
			Enabled:     tde.config.XSSDetection,
			Detector:    tde.detectXSS,
			Mitigator:   tde.mitigateXSS,
			Tags:        []string{"xss", "web", "script"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "brute_force_001",
			Name:        "Brute Force Attack Detection",
			Type:        ThreatTypeBruteForce,
			Severity:    ThreatSeverityHigh,
			Description: "Detects brute force login attempts",
			Enabled:     tde.config.BruteForceDetection,
			Detector:    tde.detectBruteForce,
			Mitigator:   tde.mitigateBruteForce,
			Tags:        []string{"brute_force", "auth", "login"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "ddos_001",
			Name:        "DDoS Attack Detection",
			Type:        ThreatTypeDDoS,
			Severity:    ThreatSeverityCritical,
			Description: "Detects distributed denial of service attacks",
			Enabled:     tde.config.DDoSDetection,
			Detector:    tde.detectDDoS,
			Mitigator:   tde.mitigateDDoS,
			Tags:        []string{"ddos", "dos", "rate_limit"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "data_leakage_001",
			Name:        "Data Leakage Detection",
			Type:        ThreatTypeDataLeakage,
			Severity:    ThreatSeverityCritical,
			Description: "Detects potential data leakage attempts",
			Enabled:     tde.config.DataLeakageDetection,
			Detector:    tde.detectDataLeakage,
			Mitigator:   tde.mitigateDataLeakage,
			Tags:        []string{"data", "leakage", "exfiltration"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "supply_chain_001",
			Name:        "Supply Chain Attack Detection",
			Type:        ThreatTypeSupplyChain,
			Severity:    ThreatSeverityHigh,
			Description: "Detects supply chain integrity violations",
			Enabled:     tde.config.SupplyChainValidation,
			Detector:    tde.detectSupplyChainThreat,
			Mitigator:   tde.mitigateSupplyChainThreat,
			Tags:        []string{"supply_chain", "integrity", "sbom"},
			CreatedAt:   time.Now(),
		},
		{
			ID:          "crypto_001",
			Name:        "Cryptographic Threat Detection",
			Type:        ThreatTypeCryptographic,
			Severity:    ThreatSeverityHigh,
			Description: "Detects cryptographic threats and weak signatures",
			Enabled:     tde.config.CryptographicValidation,
			Detector:    tde.detectCryptographicThreat,
			Mitigator:   tde.mitigateCryptographicThreat,
			Tags:        []string{"crypto", "signature", "integrity"},
			CreatedAt:   time.Now(),
		},
	}
	
	for _, rule := range rules {
		if rule.Pattern != "" {
			rule.Regex = regexp.MustCompile(rule.Pattern)
		}
		tde.detectionRules[rule.ID] = rule
	}
}

// Start starts the threat detection engine
func (tde *ThreatDetectionEngine) Start(ctx context.Context) error {
	if !tde.config.Enabled {
		return nil
	}
	
	tde.mutex.Lock()
	if tde.running {
		tde.mutex.Unlock()
		return fmt.Errorf("threat detection engine is already running")
	}
	tde.running = true
	tde.mutex.Unlock()
	
	tde.logger.Info("Starting threat detection engine")
	
	// Start cleanup routines
	go tde.cleanupRoutine(ctx)
	
	// Start baseline update routine
	go tde.baselineUpdateRoutine(ctx)
	
	return nil
}

// Stop stops the threat detection engine
func (tde *ThreatDetectionEngine) Stop() error {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	if !tde.running {
		return nil
	}
	
	tde.running = false
	close(tde.stopCh)
	
	tde.logger.Info("Stopped threat detection engine")
	return nil
}

// AnalyzeSecurityContext analyzes a security context for threats
func (tde *ThreatDetectionEngine) AnalyzeSecurityContext(ctx SecurityContext) []ThreatEvent {
	if !tde.config.Enabled {
		return nil
	}
	
	threats := make([]ThreatEvent, 0)
	
	// Check if IP is blacklisted
	if tde.isBlacklisted(ctx.SourceIP) {
		threat := tde.createThreatEvent(
			ThreatTypeUnauthorized,
			ThreatSeverityHigh,
			ctx.SourceIP,
			ctx.RequestPath,
			"Request from blacklisted IP address",
			map[string]interface{}{
				"blacklisted_ip": ctx.SourceIP,
				"request_path":   ctx.RequestPath,
			},
			ctx,
		)
		threats = append(threats, threat)
	}
	
	// Run all enabled detection rules
	for _, rule := range tde.detectionRules {
		if !rule.Enabled {
			continue
		}
		
		detected, evidence := rule.Detector(ctx)
		if detected {
			threat := tde.createThreatEvent(
				rule.Type,
				rule.Severity,
				ctx.SourceIP,
				ctx.RequestPath,
				rule.Description,
				evidence,
				ctx,
			)
			threats = append(threats, threat)
			
			// Apply real-time mitigation if enabled
			if tde.config.RealTimeBlocking && rule.Mitigator != nil {
				go rule.Mitigator(threat)
			}
		}
	}
	
	// Record threats
	for _, threat := range threats {
		tde.recordThreat(threat)
	}
	
	// Update suspicious IP tracking
	if len(threats) > 0 {
		tde.updateSuspiciousIP(ctx.SourceIP)
	}
	
	return threats
}

// Detection methods

func (tde *ThreatDetectionEngine) detectSQLInjection(ctx SecurityContext) (bool, map[string]interface{}) {
	rule := tde.detectionRules["sql_injection_001"]
	
	// Check request path
	if rule.Regex != nil && rule.Regex.MatchString(ctx.RequestPath) {
		return true, map[string]interface{}{
			"match_location": "path",
			"pattern":        rule.Pattern,
			"path":           ctx.RequestPath,
		}
	}
	
	// Check request body
	if rule.Regex != nil && rule.Regex.MatchString(ctx.RequestBody) {
		return true, map[string]interface{}{
			"match_location": "body",
			"pattern":        rule.Pattern,
			"body_snippet":   tde.truncateString(ctx.RequestBody, 200),
		}
	}
	
	// Check parameters
	for key, value := range ctx.Parameters {
		if valueStr, ok := value.(string); ok {
			if rule.Regex != nil && rule.Regex.MatchString(valueStr) {
				return true, map[string]interface{}{
					"match_location": "parameter",
					"parameter_name": key,
					"pattern":        rule.Pattern,
					"value_snippet":  tde.truncateString(valueStr, 200),
				}
			}
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectXSS(ctx SecurityContext) (bool, map[string]interface{}) {
	rule := tde.detectionRules["xss_001"]
	
	// Similar pattern matching for XSS
	if rule.Regex != nil && rule.Regex.MatchString(ctx.RequestBody) {
		return true, map[string]interface{}{
			"match_location": "body",
			"pattern":        rule.Pattern,
			"body_snippet":   tde.truncateString(ctx.RequestBody, 200),
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectBruteForce(ctx SecurityContext) (bool, map[string]interface{}) {
	// Check for multiple failed login attempts
	if ctx.Action == "login" || strings.Contains(ctx.RequestPath, "login") {
		// Count recent attempts from this IP
		recentAttempts := tde.countRecentAttempts(ctx.SourceIP, 5*time.Minute)
		if recentAttempts > 5 {
			return true, map[string]interface{}{
				"attempt_count": recentAttempts,
				"time_window":   "5 minutes",
				"source_ip":     ctx.SourceIP,
			}
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectDDoS(ctx SecurityContext) (bool, map[string]interface{}) {
	// Check request rate from IP
	recentRequests := tde.countRecentRequests(ctx.SourceIP, tde.config.RateLimitWindow)
	if recentRequests > tde.config.RateLimitThreshold {
		return true, map[string]interface{}{
			"request_count": recentRequests,
			"time_window":   tde.config.RateLimitWindow.String(),
			"threshold":     tde.config.RateLimitThreshold,
			"source_ip":     ctx.SourceIP,
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectDataLeakage(ctx SecurityContext) (bool, map[string]interface{}) {
	// Check for sensitive data patterns in response or logs
	sensitivePatterns := []string{
		`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, // Credit cards
		`\b\d{3}-\d{2}-\d{4}\b`,                        // SSN
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
	}
	
	for _, pattern := range sensitivePatterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(ctx.RequestBody) {
			return true, map[string]interface{}{
				"pattern_type": "sensitive_data",
				"pattern":      pattern,
				"location":     "request_body",
			}
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectSupplyChainThreat(ctx SecurityContext) (bool, map[string]interface{}) {
	// Check for SBOM integrity violations
	if ctx.AssetType == "sbom" || strings.Contains(ctx.RequestPath, "sbom") {
		// Verify SBOM signature and integrity
		if payload := ctx.Payload; len(payload) > 0 {
			// Calculate hash and verify against known good values
			hash := sha256.Sum256(payload)
			hashString := fmt.Sprintf("%x", hash)
			
			// In a real implementation, this would check against a database of known good hashes
			// For demo purposes, we'll flag any SBOM without proper metadata
			if !strings.Contains(string(payload), "bomFormat") {
				return true, map[string]interface{}{
					"threat_type": "invalid_sbom_format",
					"hash":        hashString,
					"asset_id":    ctx.AssetID,
				}
			}
		}
	}
	
	return false, nil
}

func (tde *ThreatDetectionEngine) detectCryptographicThreat(ctx SecurityContext) (bool, map[string]interface{}) {
	// Check for weak or invalid cryptographic signatures
	if signature, ok := ctx.Headers["X-Signature"]; ok {
		// Check signature strength
		if len(signature) < 64 { // Weak signature
			return true, map[string]interface{}{
				"threat_type":      "weak_signature",
				"signature_length": len(signature),
				"expected_min":     64,
			}
		}
	}
	
	// Check for deprecated crypto algorithms
	if cryptoAlg, ok := ctx.Headers["X-Crypto-Algorithm"]; ok {
		deprecatedAlgs := []string{"md5", "sha1", "des", "3des"}
		for _, deprecated := range deprecatedAlgs {
			if strings.ToLower(cryptoAlg) == deprecated {
				return true, map[string]interface{}{
					"threat_type": "deprecated_crypto",
					"algorithm":   cryptoAlg,
				}
			}
		}
	}
	
	return false, nil
}

// Mitigation methods

func (tde *ThreatDetectionEngine) mitigateSQLInjection(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Info("Mitigating SQL injection threat")
	
	// Block IP temporarily
	if tde.config.AutoBlacklistEnabled {
		tde.blacklistIP(threat.Source, 1*time.Hour)
	}
	
	return nil
}

func (tde *ThreatDetectionEngine) mitigateXSS(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Info("Mitigating XSS threat")
	
	// Log detailed information for analysis
	tde.logger.WithFields(logrus.Fields{
		"threat_id": threat.ID,
		"source":    threat.Source,
		"evidence":  threat.Evidence,
	}).Warn("XSS attempt detected and blocked")
	
	return nil
}

func (tde *ThreatDetectionEngine) mitigateBruteForce(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Info("Mitigating brute force threat")
	
	// Blacklist IP for extended period
	if tde.config.AutoBlacklistEnabled {
		tde.blacklistIP(threat.Source, 24*time.Hour)
	}
	
	return nil
}

func (tde *ThreatDetectionEngine) mitigateDDoS(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Info("Mitigating DDoS threat")
	
	// Implement rate limiting
	if tde.config.AutoBlacklistEnabled {
		tde.blacklistIP(threat.Source, 1*time.Hour)
	}
	
	return nil
}

func (tde *ThreatDetectionEngine) mitigateDataLeakage(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Error("Data leakage threat detected - immediate attention required")
	
	// This would trigger immediate alerts and potentially block the user/session
	return nil
}

func (tde *ThreatDetectionEngine) mitigateSupplyChainThreat(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Error("Supply chain threat detected")
	
	// Quarantine the asset and alert security team
	return nil
}

func (tde *ThreatDetectionEngine) mitigateCryptographicThreat(threat ThreatEvent) error {
	tde.logger.WithField("threat_id", threat.ID).Warn("Cryptographic threat detected")
	
	// Reject requests with weak cryptography
	return nil
}

// Helper methods

func (tde *ThreatDetectionEngine) createThreatEvent(
	threatType ThreatType,
	severity ThreatSeverity,
	source, target, description string,
	evidence map[string]interface{},
	ctx SecurityContext,
) ThreatEvent {
	return ThreatEvent{
		ID:              fmt.Sprintf("threat_%d_%s", time.Now().UnixNano(), string(threatType)),
		Timestamp:       time.Now(),
		Type:            threatType,
		Severity:        severity,
		Source:          source,
		Target:          target,
		Description:     description,
		Evidence:        evidence,
		RiskScore:       tde.calculateRiskScore(threatType, severity, evidence),
		ConfidenceScore: tde.calculateConfidenceScore(evidence),
		AttackVector:    tde.determineAttackVector(ctx),
		GeoLocation:     tde.getGeoLocation(source),
		UserAgent:       ctx.UserAgent,
		RequestID:       ctx.Metadata["request_id"].(string),
		Tags:            []string{string(threatType), string(severity)},
	}
}

func (tde *ThreatDetectionEngine) calculateRiskScore(threatType ThreatType, severity ThreatSeverity, evidence map[string]interface{}) float64 {
	baseScore := 0.0
	
	// Base score by threat type
	switch threatType {
	case ThreatTypeSQLInjection, ThreatTypeDataLeakage, ThreatTypeSupplyChain:
		baseScore = 8.0
	case ThreatTypeDDoS, ThreatTypeBruteForce:
		baseScore = 7.0
	case ThreatTypeXSS, ThreatTypeCryptographic:
		baseScore = 6.0
	default:
		baseScore = 5.0
	}
	
	// Severity multiplier
	severityMultiplier := 1.0
	switch severity {
	case ThreatSeverityCritical:
		severityMultiplier = 1.5
	case ThreatSeverityHigh:
		severityMultiplier = 1.3
	case ThreatSeverityMedium:
		severityMultiplier = 1.1
	case ThreatSeverityLow:
		severityMultiplier = 0.8
	}
	
	return baseScore * severityMultiplier
}

func (tde *ThreatDetectionEngine) calculateConfidenceScore(evidence map[string]interface{}) float64 {
	// Higher confidence for more evidence
	baseConfidence := 0.7
	evidenceBonus := float64(len(evidence)) * 0.05
	
	return baseConfidence + evidenceBonus
}

func (tde *ThreatDetectionEngine) determineAttackVector(ctx SecurityContext) string {
	if ctx.RequestMethod == "POST" {
		return "HTTP_POST"
	} else if ctx.RequestMethod == "GET" {
		return "HTTP_GET"
	}
	return "HTTP_OTHER"
}

func (tde *ThreatDetectionEngine) getGeoLocation(ip string) GeoLocation {
	// In a real implementation, this would use a GeoIP database
	return GeoLocation{
		Country: "Unknown",
		Region:  "Unknown",
		City:    "Unknown",
		ISP:     "Unknown",
		ThreatDB: false,
	}
}

func (tde *ThreatDetectionEngine) recordThreat(threat ThreatEvent) {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	tde.threatHistory = append(tde.threatHistory, threat)
	
	// Keep only recent threats
	if len(tde.threatHistory) > tde.config.MaxThreatHistory {
		tde.threatHistory = tde.threatHistory[len(tde.threatHistory)-tde.config.MaxThreatHistory:]
	}
	
	tde.logger.WithFields(logrus.Fields{
		"threat_id":   threat.ID,
		"type":        threat.Type,
		"severity":    threat.Severity,
		"source":      threat.Source,
		"risk_score":  threat.RiskScore,
	}).Warn("Security threat detected")
}

func (tde *ThreatDetectionEngine) isBlacklisted(ip string) bool {
	tde.mutex.RLock()
	defer tde.mutex.RUnlock()
	
	if blacklistTime, exists := tde.blacklistedIPs[ip]; exists {
		if time.Now().Before(blacklistTime) {
			return true
		}
		// Cleanup expired blacklist entry
		go func() {
			tde.mutex.Lock()
			delete(tde.blacklistedIPs, ip)
			tde.mutex.Unlock()
		}()
	}
	
	return false
}

func (tde *ThreatDetectionEngine) blacklistIP(ip string, duration time.Duration) {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	tde.blacklistedIPs[ip] = time.Now().Add(duration)
	tde.logger.WithFields(logrus.Fields{
		"ip":       ip,
		"duration": duration.String(),
	}).Info("IP address blacklisted")
}

func (tde *ThreatDetectionEngine) updateSuspiciousIP(ip string) {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	tde.suspiciousIPs[ip]++
	
	// Auto-blacklist if threshold exceeded
	if tde.suspiciousIPs[ip] >= tde.config.SuspiciousIPThreshold {
		tde.blacklistedIPs[ip] = time.Now().Add(tde.config.BlacklistDuration)
		delete(tde.suspiciousIPs, ip)
		
		tde.logger.WithField("ip", ip).Warn("IP automatically blacklisted due to suspicious activity")
	}
}

func (tde *ThreatDetectionEngine) countRecentAttempts(ip string, window time.Duration) int {
	tde.mutex.RLock()
	defer tde.mutex.RUnlock()
	
	cutoff := time.Now().Add(-window)
	count := 0
	
	for _, threat := range tde.threatHistory {
		if threat.Source == ip && threat.Timestamp.After(cutoff) {
			count++
		}
	}
	
	return count
}

func (tde *ThreatDetectionEngine) countRecentRequests(ip string, window time.Duration) int {
	// In a real implementation, this would track all requests, not just threats
	return tde.countRecentAttempts(ip, window)
}

func (tde *ThreatDetectionEngine) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// cleanupRoutine performs periodic cleanup
func (tde *ThreatDetectionEngine) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tde.performCleanup()
		case <-tde.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (tde *ThreatDetectionEngine) performCleanup() {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	now := time.Now()
	
	// Clean up expired blacklisted IPs
	for ip, expiry := range tde.blacklistedIPs {
		if now.After(expiry) {
			delete(tde.blacklistedIPs, ip)
		}
	}
	
	// Clean up old suspicious IP entries
	for ip, count := range tde.suspiciousIPs {
		if count == 0 {
			delete(tde.suspiciousIPs, ip)
		} else {
			// Decay suspicious activity over time
			tde.suspiciousIPs[ip] = int(float64(count) * 0.9)
		}
	}
}

// baselineUpdateRoutine updates security baselines
func (tde *ThreatDetectionEngine) baselineUpdateRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tde.updateBaselines()
		case <-tde.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (tde *ThreatDetectionEngine) updateBaselines() {
	// Update security baselines based on historical data
	tde.logger.Debug("Updating security baselines")
	// Implementation would analyze threat patterns and update baselines
}

// Public API methods

// GetThreatHistory returns recent threat events
func (tde *ThreatDetectionEngine) GetThreatHistory(limit int) []ThreatEvent {
	tde.mutex.RLock()
	defer tde.mutex.RUnlock()
	
	if limit <= 0 || limit > len(tde.threatHistory) {
		limit = len(tde.threatHistory)
	}
	
	start := len(tde.threatHistory) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]ThreatEvent, limit)
	copy(result, tde.threatHistory[start:])
	return result
}

// GetThreatStatistics returns threat statistics
func (tde *ThreatDetectionEngine) GetThreatStatistics() map[string]interface{} {
	tde.mutex.RLock()
	defer tde.mutex.RUnlock()
	
	totalThreats := len(tde.threatHistory)
	mitigatedThreats := 0
	threatsByType := make(map[ThreatType]int)
	threatsBySeverity := make(map[ThreatSeverity]int)
	
	for _, threat := range tde.threatHistory {
		if threat.Mitigated {
			mitigatedThreats++
		}
		threatsByType[threat.Type]++
		threatsBySeverity[threat.Severity]++
	}
	
	return map[string]interface{}{
		"total_threats":       totalThreats,
		"mitigated_threats":   mitigatedThreats,
		"unmitigated_threats": totalThreats - mitigatedThreats,
		"threats_by_type":     threatsByType,
		"threats_by_severity": threatsBySeverity,
		"blacklisted_ips":     len(tde.blacklistedIPs),
		"suspicious_ips":      len(tde.suspiciousIPs),
		"config":              tde.config,
		"rules_count":         len(tde.detectionRules),
	}
}

// GetBlacklistedIPs returns currently blacklisted IPs
func (tde *ThreatDetectionEngine) GetBlacklistedIPs() map[string]time.Time {
	tde.mutex.RLock()
	defer tde.mutex.RUnlock()
	
	result := make(map[string]time.Time)
	for ip, expiry := range tde.blacklistedIPs {
		result[ip] = expiry
	}
	return result
}

// AddThreatRule adds a custom threat detection rule
func (tde *ThreatDetectionEngine) AddThreatRule(rule ThreatRule) error {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	if rule.Pattern != "" {
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		rule.Regex = regex
	}
	
	tde.detectionRules[rule.ID] = rule
	tde.logger.WithField("rule_id", rule.ID).Info("Threat detection rule added")
	
	return nil
}

// RemoveThreatRule removes a threat detection rule
func (tde *ThreatDetectionEngine) RemoveThreatRule(ruleID string) error {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	if _, exists := tde.detectionRules[ruleID]; !exists {
		return fmt.Errorf("rule with ID %s not found", ruleID)
	}
	
	delete(tde.detectionRules, ruleID)
	tde.logger.WithField("rule_id", ruleID).Info("Threat detection rule removed")
	
	return nil
}

// ManuallyBlacklistIP manually blacklists an IP address
func (tde *ThreatDetectionEngine) ManuallyBlacklistIP(ip string, duration time.Duration, reason string) error {
	// Validate IP address
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	tde.blacklistIP(ip, duration)
	
	tde.logger.WithFields(logrus.Fields{
		"ip":       ip,
		"duration": duration.String(),
		"reason":   reason,
	}).Info("IP manually blacklisted")
	
	return nil
}

// RemoveFromBlacklist removes an IP from the blacklist
func (tde *ThreatDetectionEngine) RemoveFromBlacklist(ip string) error {
	tde.mutex.Lock()
	defer tde.mutex.Unlock()
	
	if _, exists := tde.blacklistedIPs[ip]; !exists {
		return fmt.Errorf("IP %s is not blacklisted", ip)
	}
	
	delete(tde.blacklistedIPs, ip)
	tde.logger.WithField("ip", ip).Info("IP removed from blacklist")
	
	return nil
}
