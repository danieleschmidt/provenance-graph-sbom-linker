package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/errors"
)

// RequestValidator provides comprehensive request validation
type RequestValidator struct {
	maxBodySize     int64
	allowedMethods  []string
	blockedUserAgents []*regexp.Regexp
	blockedHeaders    []string
}

// NewRequestValidator creates a new request validator
func NewRequestValidator() *RequestValidator {
	// Common bot/scanner user agents to block
	botPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)bot`),
		regexp.MustCompile(`(?i)crawler`),
		regexp.MustCompile(`(?i)spider`),
		regexp.MustCompile(`(?i)scraper`),
		regexp.MustCompile(`(?i)scanner`),
		regexp.MustCompile(`(?i)nikto`),
		regexp.MustCompile(`(?i)nmap`),
		regexp.MustCompile(`(?i)sqlmap`),
		regexp.MustCompile(`(?i)dirb`),
		regexp.MustCompile(`(?i)gobuster`),
	}

	return &RequestValidator{
		maxBodySize:       10 * 1024 * 1024, // 10MB
		allowedMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"},
		blockedUserAgents: botPatterns,
		blockedHeaders:    []string{"X-Forwarded-For", "X-Real-IP"},
	}
}

// ValidateRequest provides comprehensive request validation
func (rv *RequestValidator) ValidateRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate HTTP method
		if !rv.isMethodAllowed(c.Request.Method) {
			appErr := errors.NewValidationError("Method not allowed", c.Request.Method)
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		// Validate User-Agent
		userAgent := c.GetHeader("User-Agent")
		if rv.isBotUserAgent(userAgent) {
			appErr := errors.NewAuthorizationError("access", "Access denied for automated clients")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		// Validate Content-Length
		if c.Request.ContentLength > rv.maxBodySize {
			appErr := errors.NewValidationError("Request body too large", "Maximum size is 10MB")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		// Validate request headers for security
		if rv.hasBlockedHeaders(c) {
			appErr := errors.NewAuthorizationError("headers", "Blocked headers detected")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		// Validate JSON content for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			if err := rv.validateJSONContent(c); err != nil {
				c.JSON(err.StatusCode, err.ToResponse())
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// isMethodAllowed checks if HTTP method is allowed
func (rv *RequestValidator) isMethodAllowed(method string) bool {
	for _, allowed := range rv.allowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

// isBotUserAgent checks if User-Agent appears to be from a bot/scanner
func (rv *RequestValidator) isBotUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true // Block empty user agents
	}

	for _, pattern := range rv.blockedUserAgents {
		if pattern.MatchString(userAgent) {
			return true
		}
	}

	return false
}

// hasBlockedHeaders checks for headers that shouldn't be present
func (rv *RequestValidator) hasBlockedHeaders(c *gin.Context) bool {
	for _, header := range rv.blockedHeaders {
		if c.GetHeader(header) != "" {
			return true
		}
	}
	return false
}

// validateJSONContent validates JSON request body
func (rv *RequestValidator) validateJSONContent(c *gin.Context) *errors.AppError {
	contentType := c.GetHeader("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return errors.NewValidationError("Content-Type must be application/json", contentType)
	}

	// Read and validate JSON
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return errors.NewValidationError("Failed to read request body", err.Error())
	}

	// Restore body for subsequent handlers
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// Validate JSON format
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return errors.NewValidationError("Invalid JSON format", err.Error())
	}

	// Check for potentially dangerous content
	bodyStr := string(body)
	if rv.containsSuspiciousContent(bodyStr) {
		return errors.NewValidationError("Malicious content detected", "request_body")
	}

	return nil
}

// containsSuspiciousContent checks for potentially malicious content
func (rv *RequestValidator) containsSuspiciousContent(content string) bool {
	suspiciousPatterns := []string{
		"<script",
		"javascript:",
		"eval(",
		"setTimeout(",
		"setInterval(",
		"document.cookie",
		"window.location",
		"alert(",
		"confirm(",
		"prompt(",
		"onload=",
		"onerror=",
		"onclick=",
		"onmouseover=",
		"expression(",
		"vbscript:",
		"data:text/html",
		"<!--",
		"-->",
		"<?php",
		"<?=",
		"<%",
		"%>",
		"union select",
		"drop table",
		"delete from",
		"insert into",
		"update set",
		"exec(",
		"execute(",
		"sp_",
		"xp_",
		"../",
		"..\\",
		"/etc/passwd",
		"/proc/",
		"cmd.exe",
		"powershell",
		"bash",
		"/bin/",
		"${",
		"#{",
		"{{",
		"<%=",
		"<c:",
		"<jsp:",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

// ContentLengthValidator ensures content length header matches actual content
func ContentLengthValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentLength := c.Request.ContentLength
			if contentLength < 0 {
				appErr := errors.NewValidationError("Content-Length header required", "")
				c.JSON(appErr.StatusCode, appErr.ToResponse())
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// HostHeaderValidator validates the Host header
func HostHeaderValidator(allowedHosts []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.GetHeader("Host")
		if host == "" {
			appErr := errors.NewValidationError("Host header required", "")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		// Check if host is in allowed list
		hostAllowed := false
		for _, allowedHost := range allowedHosts {
			if host == allowedHost {
				hostAllowed = true
				break
			}
		}

		if !hostAllowed && len(allowedHosts) > 0 {
			appErr := errors.NewAuthorizationError("host", "Host not allowed")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			c.Abort()
			return
		}

		c.Next()
	}
}

// QueryParameterValidator validates query parameters
func QueryParameterValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for dangerous query parameters
		for param, values := range c.Request.URL.Query() {
			for _, value := range values {
				if containsInjection(param) || containsInjection(value) {
					appErr := errors.NewValidationError("Invalid query parameters", "query_parameters")
					c.JSON(appErr.StatusCode, appErr.ToResponse())
					c.Abort()
					return
				}
			}
		}
		c.Next()
	}
}

// containsInjection checks for common injection patterns
func containsInjection(input string) bool {
	injectionPatterns := []string{
		"'", "\"", ";", "=", "<", ">", "(", ")", "{", "}",
		"union", "select", "insert", "delete", "drop", "create",
		"script", "javascript", "vbscript", "onload", "onerror",
		"../", "..\\", "/etc/", "c:\\", "cmd", "powershell",
		"${", "#{", "<%", "%>", "<?", "?>",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range injectionPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	return false
}

// Note: RequestIDMiddleware moved to metrics.go to avoid duplication