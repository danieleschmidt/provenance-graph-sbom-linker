package middleware

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/security"
	"github.com/sirupsen/logrus"
)

// SecurityMiddleware provides enhanced security features
type SecurityMiddleware struct {
	threatDetector *security.ThreatDetector
	logger         *logrus.Logger
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(logger *logrus.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		threatDetector: security.NewThreatDetector(logger),
		logger:         logger,
	}
}

// EnhancedSecurity provides comprehensive security protection
func (sm *SecurityMiddleware) EnhancedSecurity() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		
		// Extract request data for analysis
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		
		// Read body if present (for POST/PUT requests)
		body := ""
		if c.Request.ContentLength > 0 && c.Request.ContentLength < 1024*1024 { // Limit to 1MB
			if bodyBytes, err := c.GetRawData(); err == nil {
				body = string(bodyBytes)
				// Reset body for downstream handlers
				c.Request.Body = io.NopCloser(strings.NewReader(body))
			}
		}
		
		// Analyze request for threats
		threats := sm.threatDetector.AnalyzeRequest(c.Request.Context(), clientIP, userAgent, path, query, body)
		
		// Handle detected threats
		for _, threat := range threats {
			sm.logger.WithFields(logrus.Fields{
				"threat_id":   threat.ID,
				"threat_type": threat.Type,
				"level":       threat.Level,
				"source":      threat.Source,
				"path":        path,
				"user_agent":  userAgent,
			}).Warn("Security threat detected in request")
			
			// Block high-severity threats
			if threat.Level >= security.ThreatLevelHigh {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Request blocked due to security policy",
					"threat_id": threat.ID,
					"timestamp": threat.Timestamp,
				})
				c.Abort()
				return
			}
		}
		
		// Add security headers
		sm.addSecurityHeaders(c)
		
		// Continue processing
		c.Next()
		
		// Log request completion
		duration := time.Since(start)
		sm.logger.WithFields(logrus.Fields{
			"client_ip":     clientIP,
			"path":          path,
			"method":        c.Request.Method,
			"status":        c.Writer.Status(),
			"duration":      duration,
			"threats_count": len(threats),
		}).Debug("Request processed by security middleware")
	})
}

// addSecurityHeaders adds comprehensive security headers
func (sm *SecurityMiddleware) addSecurityHeaders(c *gin.Context) {
	// Prevent clickjacking
	c.Header("X-Frame-Options", "DENY")
	
	// Prevent MIME type sniffing
	c.Header("X-Content-Type-Options", "nosniff")
	
	// XSS Protection
	c.Header("X-XSS-Protection", "1; mode=block")
	
	// HSTS (HTTP Strict Transport Security)
	c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	
	// Content Security Policy
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: https:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'"
	c.Header("Content-Security-Policy", csp)
	
	// Referrer Policy
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
	
	// Permissions Policy (formerly Feature Policy)
	c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	
	// Remove server information
	c.Header("Server", "")
	
	// Prevent caching of sensitive responses
	if strings.Contains(c.Request.URL.Path, "/api/") {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
	}
}

// IPWhitelisting middleware for trusted IPs
func (sm *SecurityMiddleware) IPWhitelisting(allowedIPs []string) gin.HandlerFunc {
	whitelist := make(map[string]bool)
	for _, ip := range allowedIPs {
		whitelist[ip] = true
	}
	
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		if !whitelist[clientIP] {
			sm.logger.WithFields(logrus.Fields{
				"client_ip": clientIP,
				"path":      c.Request.URL.Path,
			}).Warn("Request from non-whitelisted IP blocked")
			
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied: IP not whitelisted",
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// APIKeyAuth middleware for API key authentication
func (sm *SecurityMiddleware) APIKeyAuth(validKeys map[string]bool) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}
		
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
			})
			c.Abort()
			return
		}
		
		if !validKeys[apiKey] {
			sm.logger.WithFields(logrus.Fields{
				"api_key":   apiKey[:8] + "...", // Log partial key for security
				"client_ip": c.ClientIP(),
				"path":      c.Request.URL.Path,
			}).Warn("Invalid API key used")
			
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			c.Abort()
			return
		}
		
		c.Set("authenticated", true)
		c.Next()
	})
}

// RequestSanitization middleware to sanitize inputs
func (sm *SecurityMiddleware) RequestSanitization() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Sanitize query parameters
		values := c.Request.URL.Query()
		for key, vals := range values {
			for i, val := range vals {
				values[key][i] = sm.sanitizeInput(val)
			}
		}
		c.Request.URL.RawQuery = values.Encode()
		
		// Sanitize headers (remove potentially malicious headers)
		maliciousHeaders := []string{
			"X-Forwarded-Host",
			"X-Original-URL",
			"X-Rewrite-URL",
		}
		
		for _, header := range maliciousHeaders {
			c.Request.Header.Del(header)
		}
		
		c.Next()
	})
}

// sanitizeInput removes potentially dangerous characters from input
func (sm *SecurityMiddleware) sanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove other control characters
	result := make([]rune, 0, len(input))
	for _, r := range input {
		if r >= 32 && r != 127 { // Keep printable ASCII characters
			result = append(result, r)
		}
	}
	
	return string(result)
}

// GetThreatDetector returns the threat detector instance
func (sm *SecurityMiddleware) GetThreatDetector() *security.ThreatDetector {
	return sm.threatDetector
}