package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		
		c.Next()
	}
}

func CORS(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if len(allowedOrigins) > 0 && allowedOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Rate limiter map for IP-based rate limiting
var rateLimiters = make(map[string]*rate.Limiter)
var securityLogger = logger.NewStructuredLogger("info", "json")

func RateLimiter() gin.HandlerFunc {
	return RateLimit(100, 200) // Default: 100 requests per second, burst 200
}

// Enhanced rate limiting middleware
func RateLimit(requestsPerSecond int, burstSize int) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Get or create rate limiter for this IP
		limiter, exists := rateLimiters[clientIP]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(requestsPerSecond), burstSize)
			rateLimiters[clientIP] = limiter
		}
		
		if !limiter.Allow() {
			// Rate limit exceeded
			securityLogger.Warn("rate_limit_exceeded", map[string]interface{}{
				"message":   fmt.Sprintf("Rate limit exceeded for IP: %s", clientIP),
				"client_ip": clientIP,
				"path":      c.Request.URL.Path,
				"method":    c.Request.Method,
				"severity":  "high",
			})
			
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"retry_after": 60,
			})
			return
		}
		
		c.Next()
	}
}

func APIKeyAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		if !isValidAPIKey(apiKey) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		c.Set("api_key", apiKey)
		c.Next()
	})
}

func isValidAPIKey(key string) bool {
	if len(key) < 32 {
		return false
	}
	
	if !strings.HasPrefix(key, "pk_") && !strings.HasPrefix(key, "sk_") {
		return false
	}

	return true
}

// Request size limiting middleware
func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			securityLogger.Warn("request_size_exceeded", map[string]interface{}{
				"message":        fmt.Sprintf("Request size limit exceeded: %d > %d", c.Request.ContentLength, maxSize),
				"client_ip":      c.ClientIP(),
				"content_length": c.Request.ContentLength,
				"max_size":       maxSize,
				"severity":       "medium",
			})
			
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("Request too large. Maximum size: %d bytes", maxSize),
			})
			return
		}
		c.Next()
	}
}

// Request timeout middleware
func RequestTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simple timeout implementation
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		
		c.Request = c.Request.WithContext(ctx)
		c.Next()
		
		// Check if context was cancelled due to timeout
		if ctx.Err() == context.DeadlineExceeded {
			c.AbortWithStatusJSON(http.StatusRequestTimeout, gin.H{
				"error": "Request timeout",
			})
		}
	}
}

// Helper functions for threat detection
func isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap", "nikto", "nmap", "masscan", "nessus",
		"burp", "dirbuster", "gobuster", "wfuzz",
		"python-requests", "curl/", "wget/",
	}
	
	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	
	return false
}