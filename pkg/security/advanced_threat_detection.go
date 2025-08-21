package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ThreatDetector provides advanced security threat detection
type ThreatDetector struct {
	logger            *logrus.Logger
	ipWhitelist       map[string]bool
	blockedIPs        map[string]time.Time
	suspiciousPatterns []*regexp.Regexp
	rateLimits        map[string]*RateLimit
	mu                sync.RWMutex
}

// RateLimit tracks request rates per IP
type RateLimit struct {
	Requests   int
	Window     time.Time
	MaxRequests int
	Blocked    bool
}

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// SecurityThreat represents a detected security threat
type SecurityThreat struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	Level       ThreatLevel `json:"level"`
	Source      string      `json:"source"`
	Description string      `json:"description"`
	Evidence    interface{} `json:"evidence"`
	Timestamp   time.Time   `json:"timestamp"`
	Mitigated   bool        `json:"mitigated"`
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector(logger *logrus.Logger) *ThreatDetector {
	td := &ThreatDetector{
		logger:      logger,
		ipWhitelist: make(map[string]bool),
		blockedIPs:  make(map[string]time.Time),
		rateLimits:  make(map[string]*RateLimit),
	}
	
	// Initialize suspicious patterns
	td.initializeSuspiciousPatterns()
	
	// Add common safe IPs to whitelist
	td.ipWhitelist["127.0.0.1"] = true
	td.ipWhitelist["::1"] = true
	
	return td
}

// initializeSuspiciousPatterns sets up patterns to detect malicious requests
func (td *ThreatDetector) initializeSuspiciousPatterns() {
	patterns := []string{
		// SQL Injection patterns
		`(?i)(union\s+select|select\s+\*\s+from|drop\s+table|delete\s+from)`,
		
		// XSS patterns
		`(?i)(<script|javascript:|onload=|onerror=)`,
		
		// Path traversal patterns
		`(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)`,
		
		// Command injection patterns
		`(?i)(;|\||&)(cat|ls|pwd|whoami|id|uname)`,
		
		// LDAP injection patterns
		`(?i)(\*|\(|\)|\||&).*=.*\*`,
		
		// SSRF patterns
		`(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)`,
		
		// Malicious user agents
		`(?i)(sqlmap|nmap|masscan|zap|burpsuite|w3af|nikto)`,
	}
	
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			td.suspiciousPatterns = append(td.suspiciousPatterns, regex)
		} else {
			td.logger.WithFields(logrus.Fields{
				"pattern": pattern,
				"error":   err.Error(),
			}).Error("Failed to compile suspicious pattern")
		}
	}
}

// AnalyzeRequest analyzes an incoming request for security threats
func (td *ThreatDetector) AnalyzeRequest(ctx context.Context, ip, userAgent, path, query, body string) []SecurityThreat {
	var threats []SecurityThreat
	
	// Check if IP is blocked
	if td.isIPBlocked(ip) {
		threats = append(threats, SecurityThreat{
			ID:          td.generateThreatID("blocked_ip", ip),
			Type:        "blocked_ip",
			Level:       ThreatLevelHigh,
			Source:      ip,
			Description: "Request from blocked IP address",
			Timestamp:   time.Now(),
		})
		return threats
	}
	
	// Check rate limiting
	if td.checkRateLimit(ip) {
		threats = append(threats, SecurityThreat{
			ID:          td.generateThreatID("rate_limit", ip),
			Type:        "rate_limit_exceeded",
			Level:       ThreatLevelMedium,
			Source:      ip,
			Description: "Rate limit exceeded",
			Timestamp:   time.Now(),
		})
	}
	
	// Analyze request components for suspicious patterns
	requestData := fmt.Sprintf("%s %s %s %s", userAgent, path, query, body)
	
	for _, pattern := range td.suspiciousPatterns {
		if pattern.MatchString(requestData) {
			threatType := td.classifyThreatPattern(pattern.String())
			threats = append(threats, SecurityThreat{
				ID:          td.generateThreatID(threatType, ip),
				Type:        threatType,
				Level:       td.getThreatLevel(threatType),
				Source:      ip,
				Description: fmt.Sprintf("Suspicious pattern detected: %s", pattern.String()),
				Evidence: map[string]interface{}{
					"pattern":    pattern.String(),
					"user_agent": userAgent,
					"path":       path,
					"query":      query,
					"matched_content": td.extractMatchedContent(pattern, requestData),
				},
				Timestamp: time.Now(),
			})
		}
	}
	
	// Analyze for anomalous behavior
	if anomaly := td.detectAnomalousRequest(ip, userAgent, path); anomaly != nil {
		threats = append(threats, *anomaly)
	}
	
	// Log detected threats
	for _, threat := range threats {
		td.logger.WithFields(logrus.Fields{
			"threat_id":   threat.ID,
			"threat_type": threat.Type,
			"level":       threat.Level,
			"source":      threat.Source,
		}).Warn("Security threat detected")
		
		// Auto-mitigate high/critical threats
		if threat.Level >= ThreatLevelHigh {
			td.mitigateThreat(threat)
		}
	}
	
	return threats
}

// isIPBlocked checks if an IP address is currently blocked
func (td *ThreatDetector) isIPBlocked(ip string) bool {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	if td.ipWhitelist[ip] {
		return false
	}
	
	if blockedUntil, exists := td.blockedIPs[ip]; exists {
		if time.Now().Before(blockedUntil) {
			return true
		}
		// Block has expired
		delete(td.blockedIPs, ip)
	}
	
	return false
}

// checkRateLimit checks if an IP has exceeded rate limits
func (td *ThreatDetector) checkRateLimit(ip string) bool {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	limit, exists := td.rateLimits[ip]
	if !exists {
		td.rateLimits[ip] = &RateLimit{
			Requests:    1,
			Window:      time.Now(),
			MaxRequests: 100, // Default 100 requests per minute
		}
		return false
	}
	
	// Reset window if it's been more than a minute
	if time.Since(limit.Window) > time.Minute {
		limit.Requests = 1
		limit.Window = time.Now()
		limit.Blocked = false
		return false
	}
	
	limit.Requests++
	
	if limit.Requests > limit.MaxRequests {
		if !limit.Blocked {
			limit.Blocked = true
			return true
		}
	}
	
	return limit.Blocked
}

// detectAnomalousRequest detects anomalous request patterns
func (td *ThreatDetector) detectAnomalousRequest(ip, userAgent, path string) *SecurityThreat {
	// Check for automated scanning patterns
	if td.isAutomatedScanning(userAgent, path) {
		return &SecurityThreat{
			ID:          td.generateThreatID("automated_scanning", ip),
			Type:        "automated_scanning",
			Level:       ThreatLevelMedium,
			Source:      ip,
			Description: "Automated scanning detected",
			Evidence: map[string]interface{}{
				"user_agent": userAgent,
				"path":       path,
			},
			Timestamp: time.Now(),
		}
	}
	
	// Check for suspicious paths
	if td.isSuspiciousPath(path) {
		return &SecurityThreat{
			ID:          td.generateThreatID("suspicious_path", ip),
			Type:        "suspicious_path_access",
			Level:       ThreatLevelMedium,
			Source:      ip,
			Description: "Access to suspicious path detected",
			Evidence: map[string]interface{}{
				"path": path,
			},
			Timestamp: time.Now(),
		}
	}
	
	return nil
}

// isAutomatedScanning detects automated scanning tools
func (td *ThreatDetector) isAutomatedScanning(userAgent, path string) bool {
	// Check user agent for scanning tools
	scanningTools := []string{"sqlmap", "nmap", "masscan", "zap", "burpsuite", "w3af", "nikto", "gobuster", "dirb"}
	userAgentLower := strings.ToLower(userAgent)
	
	for _, tool := range scanningTools {
		if strings.Contains(userAgentLower, tool) {
			return true
		}
	}
	
	// Check for rapid directory enumeration patterns
	suspiciousPaths := []string{"/admin", "/.env", "/config", "/backup", "/test", "/.git"}
	pathLower := strings.ToLower(path)
	
	for _, suspPath := range suspiciousPaths {
		if strings.Contains(pathLower, suspPath) {
			return true
		}
	}
	
	return false
}

// isSuspiciousPath checks if a path is suspicious
func (td *ThreatDetector) isSuspiciousPath(path string) bool {
	suspiciousPaths := []string{
		"/.env", "/.git", "/config", "/admin", "/phpmyadmin", "/wp-admin",
		"/backup", "/test", "/debug", "/.aws", "/.ssh", "/etc/passwd",
	}
	
	pathLower := strings.ToLower(path)
	for _, suspPath := range suspiciousPaths {
		if strings.HasPrefix(pathLower, suspPath) {
			return true
		}
	}
	
	return false
}

// mitigateThreat automatically mitigates detected threats
func (td *ThreatDetector) mitigateThreat(threat SecurityThreat) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	switch threat.Type {
	case "blocked_ip", "rate_limit_exceeded", "automated_scanning", "sql_injection", "xss_attempt":
		// Block IP for 1 hour
		td.blockedIPs[threat.Source] = time.Now().Add(time.Hour)
		td.logger.WithFields(logrus.Fields{
			"ip":          threat.Source,
			"threat_type": threat.Type,
			"blocked_until": time.Now().Add(time.Hour),
		}).Info("IP address blocked due to security threat")
		
	case "suspicious_path_access":
		// Shorter block for path-based threats (15 minutes)
		td.blockedIPs[threat.Source] = time.Now().Add(15 * time.Minute)
		td.logger.WithFields(logrus.Fields{
			"ip":          threat.Source,
			"path":        threat.Evidence,
			"blocked_until": time.Now().Add(15 * time.Minute),
		}).Info("IP address temporarily blocked for suspicious path access")
	}
	
	threat.Mitigated = true
}

// classifyThreatPattern classifies the type of threat based on the pattern
func (td *ThreatDetector) classifyThreatPattern(pattern string) string {
	if strings.Contains(pattern, "union") || strings.Contains(pattern, "select") {
		return "sql_injection"
	}
	if strings.Contains(pattern, "script") || strings.Contains(pattern, "javascript") {
		return "xss_attempt"
	}
	if strings.Contains(pattern, "..") || strings.Contains(pattern, "%2e") {
		return "path_traversal"
	}
	if strings.Contains(pattern, "cat") || strings.Contains(pattern, "whoami") {
		return "command_injection"
	}
	if strings.Contains(pattern, "localhost") || strings.Contains(pattern, "127.0") {
		return "ssrf_attempt"
	}
	return "suspicious_pattern"
}

// getThreatLevel determines the threat level based on threat type
func (td *ThreatDetector) getThreatLevel(threatType string) ThreatLevel {
	switch threatType {
	case "sql_injection", "command_injection", "ssrf_attempt":
		return ThreatLevelCritical
	case "xss_attempt", "path_traversal", "automated_scanning":
		return ThreatLevelHigh
	case "rate_limit_exceeded", "suspicious_path_access":
		return ThreatLevelMedium
	default:
		return ThreatLevelLow
	}
}

// extractMatchedContent extracts the content that matched the pattern
func (td *ThreatDetector) extractMatchedContent(pattern *regexp.Regexp, content string) string {
	match := pattern.FindString(content)
	if len(match) > 100 {
		return match[:100] + "..."
	}
	return match
}

// generateThreatID generates a unique threat ID
func (td *ThreatDetector) generateThreatID(threatType, source string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", threatType, source, time.Now().Unix())))
	return hex.EncodeToString(hash[:])[:16]
}

// BlockIP manually blocks an IP address
func (td *ThreatDetector) BlockIP(ip string, duration time.Duration, reason string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	td.blockedIPs[ip] = time.Now().Add(duration)
	td.logger.WithFields(logrus.Fields{
		"ip":       ip,
		"duration": duration,
		"reason":   reason,
	}).Info("IP address manually blocked")
}

// UnblockIP removes an IP from the block list
func (td *ThreatDetector) UnblockIP(ip string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	delete(td.blockedIPs, ip)
	td.logger.WithFields(logrus.Fields{
		"ip": ip,
	}).Info("IP address unblocked")
}

// AddToWhitelist adds an IP to the whitelist
func (td *ThreatDetector) AddToWhitelist(ip string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	td.ipWhitelist[ip] = true
	// Remove from blocked list if present
	delete(td.blockedIPs, ip)
	
	td.logger.WithFields(logrus.Fields{
		"ip": ip,
	}).Info("IP address added to whitelist")
}

// GetBlockedIPs returns the list of currently blocked IPs
func (td *ThreatDetector) GetBlockedIPs() map[string]time.Time {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	result := make(map[string]time.Time)
	for ip, until := range td.blockedIPs {
		if time.Now().Before(until) {
			result[ip] = until
		}
	}
	
	return result
}