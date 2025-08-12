package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTSecret       string
	TokenExpiration time.Duration
	Issuer          string
	Audience        string
}

// AuthMiddleware provides JWT-based authentication
type AuthMiddleware struct {
	config *AuthConfig
	limiter *rate.Limiter
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config *AuthConfig) *AuthMiddleware {
	// Rate limiter: 10 requests per second with burst of 20
	limiter := rate.NewLimiter(rate.Limit(10), 20)
	
	return &AuthMiddleware{
		config:  config,
		limiter: limiter,
	}
}

// JWTAuth validates JWT tokens and sets user context
func (am *AuthMiddleware) JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Rate limiting
		if !am.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
				"code":  "MISSING_AUTH_HEADER",
			})
			c.Abort()
			return
		}

		// Check Bearer token format
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
				"code":  "INVALID_AUTH_FORMAT",
			})
			c.Abort()
			return
		}

		tokenString := bearerToken[1]

		// Parse and validate JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(am.config.JWTSecret), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
				"code":  "INVALID_TOKEN",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		// Extract claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Validate issuer
			if iss, ok := claims["iss"].(string); ok && iss != am.config.Issuer {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid token issuer",
					"code":  "INVALID_ISSUER",
				})
				c.Abort()
				return
			}

			// Validate audience
			if aud, ok := claims["aud"].(string); ok && aud != am.config.Audience {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid token audience",
					"code":  "INVALID_AUDIENCE",
				})
				c.Abort()
				return
			}

			// Set user context
			c.Set("user_id", claims["sub"])
			c.Set("user_email", claims["email"])
			c.Set("user_roles", claims["roles"])
			c.Set("user_permissions", claims["permissions"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token claims",
				"code":  "INVALID_CLAIMS",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyAuth validates API key authentication
func (am *AuthMiddleware) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Rate limiting
		if !am.limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			c.Abort()
			return
		}

		// Check for API key in header
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
				"code":  "MISSING_API_KEY",
			})
			c.Abort()
			return
		}

		// Validate API key format (should be UUID-like)
		if len(apiKey) < 32 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key format",
				"code":  "INVALID_API_KEY_FORMAT",
			})
			c.Abort()
			return
		}

		// TODO: Implement actual API key validation against database
		// For now, we'll accept any properly formatted key
		c.Set("auth_type", "api_key")
		c.Set("api_key", apiKey)

		c.Next()
	}
}

// RBAC provides role-based access control
func (am *AuthMiddleware) RBAC(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("user_roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "No roles found in token",
				"code":  "NO_ROLES",
			})
			c.Abort()
			return
		}

		roles, ok := userRoles.([]interface{})
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid roles format",
				"code":  "INVALID_ROLES_FORMAT",
			})
			c.Abort()
			return
		}

		// Convert to string slice
		userRoleStrings := make([]string, len(roles))
		for i, role := range roles {
			if roleStr, ok := role.(string); ok {
				userRoleStrings[i] = roleStr
			}
		}

		// Check if user has any of the required roles
		hasRequiredRole := false
		for _, requiredRole := range requiredRoles {
			for _, userRole := range userRoleStrings {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"code":  "INSUFFICIENT_PERMISSIONS",
				"required_roles": requiredRoles,
				"user_roles": userRoleStrings,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// OptionalAuth makes authentication optional for certain endpoints
func (am *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			// If auth header is present, validate it
			am.JWTAuth()(c)
		} else {
			// Continue without authentication
			c.Set("authenticated", false)
			c.Next()
		}
	}
}

// GenerateToken creates a new JWT token
func (am *AuthMiddleware) GenerateToken(userID, email string, roles []string, permissions []string) (string, error) {
	// Create token claims
	claims := jwt.MapClaims{
		"sub":         userID,
		"email":       email,
		"roles":       roles,
		"permissions": permissions,
		"iss":         am.config.Issuer,
		"aud":         am.config.Audience,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(am.config.TokenExpiration).Unix(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString([]byte(am.config.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a token without middleware context
func (am *AuthMiddleware) ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(am.config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// UserFromContext extracts user information from Gin context
func UserFromContext(c *gin.Context) *User {
	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("user_email")
	userRoles, _ := c.Get("user_roles")
	userPermissions, _ := c.Get("user_permissions")

	user := &User{}
	
	if userID != nil {
		if id, ok := userID.(string); ok {
			user.ID = id
		}
	}
	
	if userEmail != nil {
		if email, ok := userEmail.(string); ok {
			user.Email = email
		}
	}
	
	if userRoles != nil {
		if roles, ok := userRoles.([]interface{}); ok {
			roleStrings := make([]string, len(roles))
			for i, role := range roles {
				if roleStr, ok := role.(string); ok {
					roleStrings[i] = roleStr
				}
			}
			user.Roles = roleStrings
		}
	}
	
	if userPermissions != nil {
		if permissions, ok := userPermissions.([]interface{}); ok {
			permissionStrings := make([]string, len(permissions))
			for i, permission := range permissions {
				if permStr, ok := permission.(string); ok {
					permissionStrings[i] = permStr
				}
			}
			user.Permissions = permissionStrings
		}
	}

	return user
}

// User represents an authenticated user
type User struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	for _, userRole := range u.Roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission string) bool {
	for _, userPerm := range u.Permissions {
		if userPerm == permission {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if user has any of the specified permissions
func (u *User) HasAnyPermission(permissions ...string) bool {
	for _, permission := range permissions {
		if u.HasPermission(permission) {
			return true
		}
	}
	return false
}

// AdminOnly middleware restricts access to admin users only
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := UserFromContext(c)
		if !user.HasRole("admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Admin access required",
				"code":  "ADMIN_REQUIRED",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ReadWriteAccess middleware checks for read/write permissions
func ReadWriteAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := UserFromContext(c)
		if !user.HasAnyPermission("read", "write", "admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Read/write access required",
				"code":  "INSUFFICIENT_PERMISSIONS",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}