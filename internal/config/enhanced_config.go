package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Use embedded structs to extend the base Config
type EnhancedConfig struct {
	Config        `mapstructure:",squash"`  // Embed base config
	Observability ObservabilityConfig `mapstructure:"observability" json:"observability"`
	WorkerPool    WorkerPoolConfig    `mapstructure:"worker_pool" json:"worker_pool"`
	Cache         CacheConfig         `mapstructure:"cache" json:"cache"`
}

type EnhancedServerConfig struct {
	Port           int           `mapstructure:"port" json:"port"`
	Host           string        `mapstructure:"host" json:"host"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" json:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout" json:"write_timeout"`
	IdleTimeout    time.Duration `mapstructure:"idle_timeout" json:"idle_timeout"`
	Environment    string        `mapstructure:"environment" json:"environment"`
	TLSEnabled     bool          `mapstructure:"tls_enabled" json:"tls_enabled"`
	TLSCertFile    string        `mapstructure:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile     string        `mapstructure:"tls_key_file" json:"tls_key_file"`
	MaxHeaderBytes int           `mapstructure:"max_header_bytes" json:"max_header_bytes"`
}

type EnhancedDatabaseConfig struct {
	Neo4jURI              string        `mapstructure:"neo4j_uri" json:"neo4j_uri"`
	Neo4jUsername         string        `mapstructure:"neo4j_username" json:"neo4j_username"`
	Neo4jPassword         string        `mapstructure:"neo4j_password" json:"-"` // Don't serialize passwords
	ConnectionPool        int           `mapstructure:"connection_pool" json:"connection_pool"`
	QueryTimeout          time.Duration `mapstructure:"query_timeout" json:"query_timeout"`
	MaxRetries            int           `mapstructure:"max_retries" json:"max_retries"`
	RetryInterval         time.Duration `mapstructure:"retry_interval" json:"retry_interval"`
	HealthCheckInterval   time.Duration `mapstructure:"health_check_interval" json:"health_check_interval"`
}

type EnhancedSecurityConfig struct {
	CORSOrigins           []string      `mapstructure:"cors_origins" json:"cors_origins"`
	CORSMethods           []string      `mapstructure:"cors_methods" json:"cors_methods"`
	CORSHeaders           []string      `mapstructure:"cors_headers" json:"cors_headers"`
	CORSCredentials       bool          `mapstructure:"cors_credentials" json:"cors_credentials"`
	RateLimitEnabled      bool          `mapstructure:"rate_limit_enabled" json:"rate_limit_enabled"`
	RateLimitRPS          int           `mapstructure:"rate_limit_rps" json:"rate_limit_rps"`
	RateLimitBurst        int           `mapstructure:"rate_limit_burst" json:"rate_limit_burst"`
	JWTSecretKey          string        `mapstructure:"jwt_secret_key" json:"-"`
	JWTExpirationTime     time.Duration `mapstructure:"jwt_expiration_time" json:"jwt_expiration_time"`
	AllowedSignatureTypes []string      `mapstructure:"allowed_signature_types" json:"allowed_signature_types"`
	MaxUploadSize         int64         `mapstructure:"max_upload_size" json:"max_upload_size"`
}

type ObservabilityConfig struct {
	Enabled         bool   `mapstructure:"enabled" json:"enabled"`
	OTLPEndpoint    string `mapstructure:"otlp_endpoint" json:"otlp_endpoint"`
	ServiceName     string `mapstructure:"service_name" json:"service_name"`
	ServiceVersion  string `mapstructure:"service_version" json:"service_version"`
	MetricsEnabled  bool   `mapstructure:"metrics_enabled" json:"metrics_enabled"`
	TracingEnabled  bool   `mapstructure:"tracing_enabled" json:"tracing_enabled"`
	MetricsPort     int    `mapstructure:"metrics_port" json:"metrics_port"`
	HealthCheckPath string `mapstructure:"health_check_path" json:"health_check_path"`
}

type WorkerPoolConfig struct {
	Size         int           `mapstructure:"size" json:"size"`
	QueueSize    int           `mapstructure:"queue_size" json:"queue_size"`
	Timeout      time.Duration `mapstructure:"timeout" json:"timeout"`
	MaxRetries   int           `mapstructure:"max_retries" json:"max_retries"`
	RetryBackoff time.Duration `mapstructure:"retry_backoff" json:"retry_backoff"`
}

type CacheConfig struct {
	Enabled    bool          `mapstructure:"enabled" json:"enabled"`
	RedisURL   string        `mapstructure:"redis_url" json:"redis_url"`
	TTL        time.Duration `mapstructure:"ttl" json:"ttl"`
	MaxSize    int           `mapstructure:"max_size" json:"max_size"`
	Eviction   string        `mapstructure:"eviction" json:"eviction"`
}

func LoadEnhanced() (*EnhancedConfig, error) {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.tls_enabled", false)
	viper.SetDefault("server.max_header_bytes", 1048576) // 1MB

	// Database defaults
	viper.SetDefault("database.neo4j_uri", "bolt://localhost:7687")
	viper.SetDefault("database.neo4j_username", "neo4j")
	viper.SetDefault("database.neo4j_password", "password")
	viper.SetDefault("database.connection_pool", 50)
	viper.SetDefault("database.query_timeout", "30s")
	viper.SetDefault("database.max_retries", 3)
	viper.SetDefault("database.retry_interval", "1s")
	viper.SetDefault("database.health_check_interval", "30s")

	// Security defaults
	viper.SetDefault("security.cors_origins", []string{"*"})
	viper.SetDefault("security.cors_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("security.cors_headers", []string{"*"})
	viper.SetDefault("security.cors_credentials", false)
	viper.SetDefault("security.rate_limit_enabled", true)
	viper.SetDefault("security.rate_limit_rps", 100)
	viper.SetDefault("security.rate_limit_burst", 200)
	viper.SetDefault("security.jwt_expiration_time", "24h")
	viper.SetDefault("security.allowed_signature_types", []string{"cosign", "gpg", "x509"})
	viper.SetDefault("security.max_upload_size", 104857600) // 100MB

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	// Observability defaults
	viper.SetDefault("observability.enabled", true)
	viper.SetDefault("observability.service_name", "provenance-linker")
	viper.SetDefault("observability.service_version", "1.0.0")
	viper.SetDefault("observability.metrics_enabled", true)
	viper.SetDefault("observability.tracing_enabled", true)
	viper.SetDefault("observability.metrics_port", 9090)
	viper.SetDefault("observability.health_check_path", "/health")

	// Worker pool defaults
	viper.SetDefault("worker_pool.size", 10)
	viper.SetDefault("worker_pool.queue_size", 1000)
	viper.SetDefault("worker_pool.timeout", "30s")
	viper.SetDefault("worker_pool.max_retries", 3)
	viper.SetDefault("worker_pool.retry_backoff", "1s")

	// Cache defaults
	viper.SetDefault("cache.enabled", false)
	viper.SetDefault("cache.redis_url", "redis://localhost:6379")
	viper.SetDefault("cache.ttl", "1h")
	viper.SetDefault("cache.max_size", 10000)
	viper.SetDefault("cache.eviction", "lru")

	// Configuration file lookup
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/provenance-linker")
	viper.AddConfigPath("$HOME/.provenance-linker")

	// Environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("PROVENANCE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is okay, we'll use defaults
	}

	// Override with environment variables if they exist
	if uri := os.Getenv("NEO4J_URI"); uri != "" {
		viper.Set("database.neo4j_uri", uri)
	}
	if username := os.Getenv("NEO4J_USERNAME"); username != "" {
		viper.Set("database.neo4j_username", username)
	}
	if password := os.Getenv("NEO4J_PASSWORD"); password != "" {
		viper.Set("database.neo4j_password", password)
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		viper.Set("cache.redis_url", redisURL)
		viper.Set("cache.enabled", true)
	}
	if otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); otlpEndpoint != "" {
		viper.Set("observability.otlp_endpoint", otlpEndpoint)
	}

	var config EnhancedConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validation
	if err := validateEnhancedConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// Validate configuration values
func validateEnhancedConfig(config *EnhancedConfig) error {
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Database.URI == "" {
		return fmt.Errorf("database URI is required")
	}

	if config.WorkerPool.Size < 1 {
		return fmt.Errorf("worker pool size must be at least 1")
	}

	return nil
}

// Convert basic config to enhanced config for backwards compatibility
func ToEnhanced(basic *Config) *EnhancedConfig {
	return &EnhancedConfig{
		Config: *basic,  // Embed the base config
		// Set enhanced defaults
		Observability: ObservabilityConfig{
			Enabled:        true,
			ServiceName:    "provenance-linker",
			ServiceVersion: "1.0.0",
			MetricsEnabled: true,
			TracingEnabled: true,
			MetricsPort:    9090,
			HealthCheckPath: "/health",
		},
		WorkerPool: WorkerPoolConfig{
			Size:         10,
			QueueSize:    1000,
			Timeout:      30 * time.Second,
			MaxRetries:   3,
			RetryBackoff: time.Second,
		},
		Cache: CacheConfig{
			Enabled:  false,
			TTL:      time.Hour,
			MaxSize:  10000,
			Eviction: "lru",
		},
	}
}