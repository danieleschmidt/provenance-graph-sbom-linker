package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Environment   string                `mapstructure:"environment"`
	Version       string                `mapstructure:"version"`
	Server        ServerConfig          `mapstructure:"server"`
	Database      DatabaseConfig        `mapstructure:"database"`
	Redis         RedisConfig           `mapstructure:"redis"`
	Security      SecurityConfig        `mapstructure:"security"`
	Logging       LoggingConfig         `mapstructure:"logging"`
	Observability ObservabilityConfig   `mapstructure:"observability"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

type DatabaseConfig struct {
	URI            string `mapstructure:"uri"`
	Username       string `mapstructure:"username"`
	Password       string `mapstructure:"password"`
	MaxConnections int    `mapstructure:"max_connections"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type SecurityConfig struct {
	JWTSecret       string        `mapstructure:"jwt_secret"`
	TokenExpiration time.Duration `mapstructure:"token_expiration"`
	CORSOrigins     []string      `mapstructure:"cors_origins"`
	RateLimit       int           `mapstructure:"rate_limit"`
}

type ObservabilityConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Endpoint        string        `mapstructure:"endpoint"`
	MetricsInterval time.Duration `mapstructure:"metrics_interval"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/provenance-linker")

	// Set environment variable prefix
	viper.SetEnvPrefix("PROVENANCE")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults from DefaultConfig
	defaultCfg := DefaultConfig()
	setDefaults(defaultCfg)

	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, continue with defaults
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Environment: "development",
		Version:     "dev",
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Database: DatabaseConfig{
			URI:            "bolt://localhost:7687",
			Username:       "neo4j",
			Password:       "password",
			MaxConnections: 50,
		},
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
		},
		Security: SecurityConfig{
			JWTSecret:       "default-secret-change-in-production",
			TokenExpiration: 24 * time.Hour,
			CORSOrigins:     []string{"*"},
			RateLimit:       1000,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Observability: ObservabilityConfig{
			Enabled:         true,
			Endpoint:        "http://localhost:4317",
			MetricsInterval: 30 * time.Second,
		},
	}
}

func setDefaults(cfg *Config) {
	viper.SetDefault("environment", cfg.Environment)
	viper.SetDefault("version", cfg.Version)
	viper.SetDefault("server.host", cfg.Server.Host)
	viper.SetDefault("server.port", cfg.Server.Port)
	viper.SetDefault("server.read_timeout", cfg.Server.ReadTimeout)
	viper.SetDefault("server.write_timeout", cfg.Server.WriteTimeout)
	viper.SetDefault("server.idle_timeout", cfg.Server.IdleTimeout)
	viper.SetDefault("database.uri", cfg.Database.URI)
	viper.SetDefault("database.username", cfg.Database.Username)
	viper.SetDefault("database.password", cfg.Database.Password)
	viper.SetDefault("database.max_connections", cfg.Database.MaxConnections)
	viper.SetDefault("redis.host", cfg.Redis.Host)
	viper.SetDefault("redis.port", cfg.Redis.Port)
	viper.SetDefault("redis.password", cfg.Redis.Password)
	viper.SetDefault("redis.db", cfg.Redis.DB)
	viper.SetDefault("observability.enabled", cfg.Observability.Enabled)
	viper.SetDefault("observability.endpoint", cfg.Observability.Endpoint)
	viper.SetDefault("observability.metrics_interval", cfg.Observability.MetricsInterval)
	viper.SetDefault("security.jwt_secret", cfg.Security.JWTSecret)
	viper.SetDefault("security.cors_origins", cfg.Security.CORSOrigins)
	viper.SetDefault("security.rate_limit", cfg.Security.RateLimit)
	viper.SetDefault("logging.level", cfg.Logging.Level)
	viper.SetDefault("logging.format", cfg.Logging.Format)
}

func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	
	if c.Database.URI == "" {
		return fmt.Errorf("database URI is required")
	}
	
	if c.Security.JWTSecret == "" || c.Security.JWTSecret == "default-secret-change-in-production" {
		if c.Environment == "production" {
			return fmt.Errorf("JWT secret must be set in production")
		}
	}
	
	return nil
}