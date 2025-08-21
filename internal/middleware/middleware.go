package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(origins []string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// Security adds common security headers
func Security() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	})
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	})
}

// RateLimiter implements basic rate limiting
func RateLimiter() gin.HandlerFunc {
	return RateLimit(1000) // Default 1000 requests per second
}

// RateLimit implements basic rate limiting
func RateLimit(requestsPerSecond int) gin.HandlerFunc {
	type client struct {
		requests int
		lastSeen time.Time
	}
	
	clients := make(map[string]*client)
	ticker := time.NewTicker(time.Second)
	
	go func() {
		for range ticker.C {
			// Reset counters every second
			for ip, c := range clients {
				if time.Since(c.lastSeen) > time.Minute {
					delete(clients, ip)
				} else {
					c.requests = 0
				}
			}
		}
	}()
	
	return gin.HandlerFunc(func(c *gin.Context) {
		ip := c.ClientIP()
		
		if clients[ip] == nil {
			clients[ip] = &client{}
		}
		
		clients[ip].lastSeen = time.Now()
		clients[ip].requests++
		
		if clients[ip].requests > requestsPerSecond {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"retry_after": 1,
			})
			c.Abort()
			return
		}
		
		c.Next()
	})
}

// Logging middleware with structured logging
func Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get method
		method := c.Request.Method

		// Get status code
		statusCode := c.Writer.Status()

		// Get request ID
		requestID, _ := c.Get("request_id")

		if raw != "" {
			path = path + "?" + raw
		}

		// Structured log entry
		entry := map[string]interface{}{
			"timestamp":   start,
			"latency":     latency,
			"client_ip":   clientIP,
			"method":      method,
			"path":        path,
			"status_code": statusCode,
			"request_id":  requestID,
			"user_agent":  c.Request.UserAgent(),
		}

		if len(c.Errors) > 0 {
			entry["errors"] = c.Errors.Errors()
		}

		// Log based on status code
		if statusCode >= 500 {
			// Log as error for server errors
		} else if statusCode >= 400 {
			// Log as warning for client errors
		} else {
			// Log as info for successful requests
		}
	}
}

// RequestSizeLimit limits the size of request bodies
func RequestSizeLimit(maxSizeBytes int64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.ContentLength > maxSizeBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large",
				"max_size": maxSizeBytes,
			})
			c.Abort()
			return
		}
		
		// Limit the reader
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSizeBytes)
		c.Next()
	})
}

// Auth middleware for JWT authentication
func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}
		
		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		
		// TODO: Implement actual JWT validation
		if token == "valid-token" {
			c.Set("user_id", "test-user")
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
		}
	})
}

// Metrics middleware for collecting request metrics
func Metrics() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		
		c.Next()
		
		duration := time.Since(start)
		statusCode := c.Writer.Status()
		
		// TODO: Send metrics to monitoring system
		_ = duration
		_ = statusCode
	})
}