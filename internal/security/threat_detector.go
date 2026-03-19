package security

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ThreatLevel defines the severity of a detected threat
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// ThreatType categorizes different types of threats
type ThreatType string

const (
	ThreatTypeMaliciousCode     ThreatType = "malicious_code"
	ThreatTypeSupplyChainAttack ThreatType = "supply_chain_attack"
	ThreatTypeSignatureForgery  ThreatType = "signature_forgery"
	ThreatTypeDataTampering     ThreatType = "data_tampering"
	ThreatTypeInjection         ThreatType = "injection_attack"
	ThreatTypeAnomalous         ThreatType = "anomalous_behavior"
)

// ThreatDetection represents a detected threat
type ThreatDetection struct {
	ID          uuid.UUID              `json:"id"`
	Type        ThreatType             `json:"type"`
	Level       ThreatLevel            `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	ArtifactID  uuid.UUID              `json:"artifact_id,omitempty"`
	Evidence    []ThreatEvidence       `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata"`
	Mitigated   bool                   `json:"mitigated"`
}

// ThreatEvidence contains evidence supporting a threat detection
type ThreatEvidence struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Confidence  float64     `json:"confidence"` // 0.0 to 1.0
}

// ThreatDetector provides comprehensive threat detection capabilities
type ThreatDetector struct {
	logger          *logrus.Logger
	detectors       map[string]Detector
	rules           map[string]DetectionRule
	whitelist       map[string]bool
	mutex           sync.RWMutex
	alertThreshold  ThreatLevel
	detections      []ThreatDetection
	maxDetections   int
}

// Detector interface for different types of threat detectors
type Detector interface {
	Name() string
	Detect(ctx context.Context, artifact *types.Artifact) []ThreatDetection
}

// DetectionRule interface for threat detection rules
type DetectionRule interface {
	Name() string
	Match(ctx context.Context, data interface{}) *ThreatDetection
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector(logger *logrus.Logger, alertThreshold ThreatLevel, maxDetections int) *ThreatDetector {
	if logger == nil {
		logger = logrus.New()
	}

	detector := &ThreatDetector{
		logger:         logger,
		detectors:      make(map[string]Detector),
		rules:          make(map[string]DetectionRule),
		whitelist:      make(map[string]bool),
		alertThreshold: alertThreshold,
		maxDetections:  maxDetections,
		detections:     make([]ThreatDetection, 0, maxDetections),
	}

	// Register built-in detectors
	detector.registerBuiltInDetectors()
	detector.registerBuiltInRules()

	return detector
}

// ScanArtifact performs comprehensive threat detection on an artifact
func (td *ThreatDetector) ScanArtifact(ctx context.Context, artifact *types.Artifact) []ThreatDetection {
	start := time.Now()
	var allDetections []ThreatDetection

	td.logger.WithFields(logrus.Fields{
		"artifact_id":   artifact.ID.String(),
		"artifact_name": artifact.Name,
	}).Info("Starting threat detection scan")

	// Run all registered detectors
	td.mutex.RLock()
	detectors := make([]Detector, 0, len(td.detectors))
	for _, detector := range td.detectors {
		detectors = append(detectors, detector)
	}
	td.mutex.RUnlock()

	for _, detector := range detectors {
		detections := detector.Detect(ctx, artifact)
		for _, detection := range detections {
			// Check if detection is whitelisted
			if !td.isWhitelisted(detection) {
				allDetections = append(allDetections, detection)
			}
		}
	}

	// Store detections (keep only recent ones)
	td.mutex.Lock()
	for _, detection := range allDetections {
		td.addDetection(detection)
	}
	td.mutex.Unlock()

	scanDuration := time.Since(start)
	td.logger.WithFields(logrus.Fields{
		"artifact_id":     artifact.ID.String(),
		"detections":      len(allDetections),
		"scan_duration":   scanDuration,
		"high_threats":    td.countThreatsByLevel(allDetections, ThreatLevelHigh),
		"critical_threats": td.countThreatsByLevel(allDetections, ThreatLevelCritical),
	}).Info("Threat detection scan completed")

	return allDetections
}

// GetDetections returns recent threat detections
func (td *ThreatDetector) GetDetections(limit int) []ThreatDetection {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	if limit <= 0 || limit > len(td.detections) {
		limit = len(td.detections)
	}

	result := make([]ThreatDetection, limit)
	copy(result, td.detections[:limit])
	return result
}

// GetThreatSummary returns a summary of recent threats
func (td *ThreatDetector) GetThreatSummary() map[string]interface{} {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	summary := map[string]interface{}{
		"total_detections": len(td.detections),
		"by_level": map[ThreatLevel]int{
			ThreatLevelLow:      0,
			ThreatLevelMedium:   0,
			ThreatLevelHigh:     0,
			ThreatLevelCritical: 0,
		},
		"by_type": make(map[ThreatType]int),
		"last_scan": time.Time{},
	}

	for _, detection := range td.detections {
		summary["by_level"].(map[ThreatLevel]int)[detection.Level]++
		summary["by_type"].(map[ThreatType]int)[detection.Type]++
		if detection.Timestamp.After(summary["last_scan"].(time.Time)) {
			summary["last_scan"] = detection.Timestamp
		}
	}

	return summary
}

// AddToWhitelist adds an item to the threat detection whitelist
func (td *ThreatDetector) AddToWhitelist(identifier string) {
	td.mutex.Lock()
	defer td.mutex.Unlock()
	td.whitelist[identifier] = true
	td.logger.WithField("identifier", identifier).Info("Added to threat detection whitelist")
}

// Built-in detectors and rules
func (td *ThreatDetector) registerBuiltInDetectors() {
	td.detectors["malicious_patterns"] = &MaliciousPatternsDetector{logger: td.logger}
	td.detectors["signature_validator"] = &SignatureValidatorDetector{logger: td.logger}
	td.detectors["hash_validator"] = &HashValidatorDetector{logger: td.logger}
	td.detectors["metadata_analyzer"] = &MetadataAnalyzerDetector{logger: td.logger}
}

func (td *ThreatDetector) registerBuiltInRules() {
	td.rules["suspicious_names"] = &SuspiciousNamesRule{}
	td.rules["weak_hashes"] = &WeakHashesRule{}
	td.rules["unsigned_artifacts"] = &UnsignedArtifactsRule{}
}

// Helper methods
func (td *ThreatDetector) addDetection(detection ThreatDetection) {
	// Add to beginning of slice (most recent first)
	td.detections = append([]ThreatDetection{detection}, td.detections...)
	
	// Trim to max size
	if len(td.detections) > td.maxDetections {
		td.detections = td.detections[:td.maxDetections]
	}
}

func (td *ThreatDetector) isWhitelisted(detection ThreatDetection) bool {
	// Check various whitelist patterns
	whitelistKeys := []string{
		detection.ArtifactID.String(),
		fmt.Sprintf("%s:%s", detection.Type, detection.Title),
		detection.Source,
	}
	
	for _, key := range whitelistKeys {
		if td.whitelist[key] {
			return true
		}
	}
	
	return false
}

func (td *ThreatDetector) countThreatsByLevel(detections []ThreatDetection, level ThreatLevel) int {
	count := 0
	for _, detection := range detections {
		if detection.Level == level {
			count++
		}
	}
	return count
}

// Built-in detector implementations
type MaliciousPatternsDetector struct {
	logger *logrus.Logger
}

func (mpd *MaliciousPatternsDetector) Name() string {
	return "malicious_patterns"
}

func (mpd *MaliciousPatternsDetector) Detect(ctx context.Context, artifact *types.Artifact) []ThreatDetection {
	var detections []ThreatDetection
	
	// Check for suspicious patterns in artifact name
	suspiciousPatterns := []string{
		`(?i)(malware|virus|trojan|backdoor|exploit)`,
		`(?i)(keylogger|rootkit|botnet|ransomware)`,
		`(?i)(shell|cmd|exec|eval|system).*\.(exe|bat|sh|ps1)$`,
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, artifact.Name); matched {
			detections = append(detections, ThreatDetection{
				ID:          uuid.New(),
				Type:        ThreatTypeMaliciousCode,
				Level:       ThreatLevelHigh,
				Title:       "Suspicious artifact name detected",
				Description: fmt.Sprintf("Artifact name '%s' matches malicious pattern", artifact.Name),
				ArtifactID:  artifact.ID,
				Evidence: []ThreatEvidence{{
					Type:        "pattern_match",
					Description: "Artifact name matches known malicious pattern",
					Value:       pattern,
					Confidence:  0.8,
				}},
				Timestamp: time.Now(),
				Source:    mpd.Name(),
				Metadata:  map[string]interface{}{"pattern": pattern},
			})
		}
	}
	
	return detections
}

type SignatureValidatorDetector struct {
	logger *logrus.Logger
}

func (svd *SignatureValidatorDetector) Name() string {
	return "signature_validator"
}

func (svd *SignatureValidatorDetector) Detect(ctx context.Context, artifact *types.Artifact) []ThreatDetection {
	var detections []ThreatDetection
	
	if len(artifact.Signatures) == 0 {
		detections = append(detections, ThreatDetection{
			ID:          uuid.New(),
			Type:        ThreatTypeSupplyChainAttack,
			Level:       ThreatLevelMedium,
			Title:       "Unsigned artifact detected",
			Description: "Artifact lacks cryptographic signatures",
			ArtifactID:  artifact.ID,
			Evidence: []ThreatEvidence{{
				Type:        "missing_signatures",
				Description: "No cryptographic signatures found",
				Value:       len(artifact.Signatures),
				Confidence:  1.0,
			}},
			Timestamp: time.Now(),
			Source:    svd.Name(),
			Metadata:  map[string]interface{}{"signature_count": 0},
		})
	}
	
	// Check for weak signature algorithms
	for i, sig := range artifact.Signatures {
		if sig.Algorithm == types.SignatureTypeGPG {
			// This is a simplified check - real implementation would validate GPG signature strength
			if strings.Contains(strings.ToLower(sig.Value), "md5") || strings.Contains(strings.ToLower(sig.Value), "sha1") {
				detections = append(detections, ThreatDetection{
					ID:          uuid.New(),
					Type:        ThreatTypeSignatureForgery,
					Level:       ThreatLevelMedium,
					Title:       "Weak signature algorithm detected",
					Description: fmt.Sprintf("Signature %d uses weak cryptographic algorithm", i),
					ArtifactID:  artifact.ID,
					Evidence: []ThreatEvidence{{
						Type:        "weak_signature",
						Description: "Signature uses weak hash algorithm",
						Value:       sig.Algorithm,
						Confidence:  0.9,
					}},
					Timestamp: time.Now(),
					Source:    svd.Name(),
					Metadata:  map[string]interface{}{"signature_index": i, "algorithm": sig.Algorithm},
				})
			}
		}
	}
	
	return detections
}

type HashValidatorDetector struct {
	logger *logrus.Logger
}

func (hvd *HashValidatorDetector) Name() string {
	return "hash_validator"
}

func (hvd *HashValidatorDetector) Detect(ctx context.Context, artifact *types.Artifact) []ThreatDetection {
	var detections []ThreatDetection
	
	if artifact.Hash == "" {
		detections = append(detections, ThreatDetection{
			ID:          uuid.New(),
			Type:        ThreatTypeDataTampering,
			Level:       ThreatLevelMedium,
			Title:       "Missing integrity hash",
			Description: "Artifact lacks integrity verification hash",
			ArtifactID:  artifact.ID,
			Evidence: []ThreatEvidence{{
				Type:        "missing_hash",
				Description: "No integrity hash provided",
				Value:       "",
				Confidence:  1.0,
			}},
			Timestamp: time.Now(),
			Source:    hvd.Name(),
			Metadata:  map[string]interface{}{"hash_present": false},
		})
	} else {
		// Check hash format and strength
		hashLen := len(artifact.Hash)
		var hashType string
		var level ThreatLevel = ThreatLevelLow
		
		switch hashLen {
		case 32:
			hashType = "MD5"
			level = ThreatLevelHigh // MD5 is cryptographically broken
		case 40:
			hashType = "SHA-1"
			level = ThreatLevelMedium // SHA-1 is deprecated
		case 64:
			hashType = "SHA-256"
			level = ThreatLevelLow // SHA-256 is acceptable
		case 128:
			hashType = "SHA-512"
			level = ThreatLevelLow // SHA-512 is strong
		default:
			hashType = "Unknown"
			level = ThreatLevelMedium
		}
		
		if level > ThreatLevelLow {
			detections = append(detections, ThreatDetection{
				ID:          uuid.New(),
				Type:        ThreatTypeDataTampering,
				Level:       level,
				Title:       "Weak hash algorithm detected",
				Description: fmt.Sprintf("Artifact uses %s hash which is cryptographically weak", hashType),
				ArtifactID:  artifact.ID,
				Evidence: []ThreatEvidence{{
					Type:        "weak_hash",
					Description: fmt.Sprintf("%s hash algorithm is not recommended", hashType),
					Value:       hashType,
					Confidence:  1.0,
				}},
				Timestamp: time.Now(),
				Source:    hvd.Name(),
				Metadata:  map[string]interface{}{"hash_type": hashType, "hash_length": hashLen},
			})
		}
	}
	
	return detections
}

type MetadataAnalyzerDetector struct {
	logger *logrus.Logger
}

func (mad *MetadataAnalyzerDetector) Name() string {
	return "metadata_analyzer"
}

func (mad *MetadataAnalyzerDetector) Detect(ctx context.Context, artifact *types.Artifact) []ThreatDetection {
	var detections []ThreatDetection
	
	// Check for suspicious metadata patterns
	for key, value := range artifact.Metadata {
		// Check for injection patterns in metadata
		suspiciousValues := []string{
			`<script`, `javascript:`, `eval\(`, `exec\(`,
			`'; DROP TABLE`, `UNION SELECT`, `<iframe`,
			`${`, `#{`, `{{`,
		}
		
		for _, suspicious := range suspiciousValues {
			if matched, _ := regexp.MatchString(`(?i)`+suspicious, value); matched {
				detections = append(detections, ThreatDetection{
					ID:          uuid.New(),
					Type:        ThreatTypeInjection,
					Level:       ThreatLevelHigh,
					Title:       "Potential injection attack in metadata",
					Description: fmt.Sprintf("Metadata field '%s' contains suspicious content", key),
					ArtifactID:  artifact.ID,
					Evidence: []ThreatEvidence{{
						Type:        "injection_pattern",
						Description: "Metadata contains potential injection payload",
						Value:       value,
						Confidence:  0.85,
					}},
					Timestamp: time.Now(),
					Source:    mad.Name(),
					Metadata:  map[string]interface{}{"metadata_key": key, "suspicious_pattern": suspicious},
				})
			}
		}
	}
	
	return detections
}

// Built-in rule implementations
type SuspiciousNamesRule struct{}
func (r *SuspiciousNamesRule) Name() string { return "suspicious_names" }
func (r *SuspiciousNamesRule) Match(ctx context.Context, data interface{}) *ThreatDetection { return nil }

type WeakHashesRule struct{}
func (r *WeakHashesRule) Name() string { return "weak_hashes" }
func (r *WeakHashesRule) Match(ctx context.Context, data interface{}) *ThreatDetection { return nil }

type UnsignedArtifactsRule struct{}
func (r *UnsignedArtifactsRule) Name() string { return "unsigned_artifacts" }
func (r *UnsignedArtifactsRule) Match(ctx context.Context, data interface{}) *ThreatDetection { return nil }