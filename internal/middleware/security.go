package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Security headers middleware
func Security() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Security headers
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// Remove server information
		c.Header("Server", "")
		
		c.Next()
	})
}

// CORS middleware with configurable origins
func CORS(allowedOrigins []string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "3600")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		
		c.Next()
	})
}

// Rate limiter middleware
func RateLimiter() gin.HandlerFunc {
	// Create rate limiter: 100 requests per minute per IP
	limiter := rate.NewLimiter(rate.Every(time.Minute/100), 100)
	
	return gin.HandlerFunc(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"retry_after": 60,
			})
			c.Abort()
			return
		}
		c.Next()
	})
}

// Request size limit middleware
func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	})
}

// Security validation middleware
func SecurityValidation() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check for common attack patterns in headers
		userAgent := c.GetHeader("User-Agent")
		if containsSQLInjection(userAgent) || containsXSS(userAgent) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			c.Abort()
			return
		}
		
		// Validate request path for directory traversal
		if strings.Contains(c.Request.URL.Path, "..") || 
		   strings.Contains(c.Request.URL.Path, "~") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request path",
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// Request logging middleware
func RequestLogging() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return ""
	})
}

// Helper functions for security validation
func containsSQLInjection(input string) bool {
	sqlPatterns := []string{
		"union", "select", "insert", "update", "delete", "drop", "create",
		"alter", "exec", "execute", "sp_", "xp_", "--", "/*", "*/",
	}
	
	lowerInput := strings.ToLower(input)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}
	return false
}

func containsXSS(input string) bool {
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "onclick=", "onerror=",
		"onload=", "alert(", "document.cookie", "window.location",
	}
	
	lowerInput := strings.ToLower(input)
	for _, pattern := range xssPatterns {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}
	return false
}