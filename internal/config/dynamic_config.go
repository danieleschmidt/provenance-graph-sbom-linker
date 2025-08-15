package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// DynamicConfigManager provides dynamic configuration management with hot-reloading
type DynamicConfigManager struct {
	config      *EnhancedConfig
	configPath  string
	watcher     *fsnotify.Watcher
	subscribers []ConfigSubscriber
	logger      *logrus.Logger
	mutex       sync.RWMutex
	running     bool
	stopCh      chan struct{}
}

// EnhancedConfig extends the base configuration with self-healing settings
type EnhancedConfig struct {
	Server      ServerConfig      `yaml:"server" json:"server"`
	Database    DatabaseConfig    `yaml:"database" json:"database"`
	SelfHealing SelfHealingConfig `yaml:"self_healing" json:"self_healing"`
	Security    SecurityConfig    `yaml:"security" json:"security"`
	Monitoring  MonitoringConfig  `yaml:"monitoring" json:"monitoring"`
	Logging     LoggingConfig     `yaml:"logging" json:"logging"`
	Features    FeatureConfig     `yaml:"features" json:"features"`
	Limits      LimitsConfig      `yaml:"limits" json:"limits"`
	UpdatedAt   time.Time         `yaml:"updated_at" json:"updated_at"`
	Version     string            `yaml:"version" json:"version"`
}

// SelfHealingConfig contains all self-healing related configurations
type SelfHealingConfig struct {
	Enabled                bool                  `yaml:"enabled" json:"enabled"`
	Pipeline              PipelineConfig        `yaml:"pipeline" json:"pipeline"`
	AnomalyDetection      AnomalyConfig         `yaml:"anomaly_detection" json:"anomaly_detection"`
	AutoScaling           AutoScalingConfig     `yaml:"auto_scaling" json:"auto_scaling"`
	ErrorHandling         ErrorHandlingConfig   `yaml:"error_handling" json:"error_handling"`
	ThreatDetection       ThreatDetectionConfig `yaml:"threat_detection" json:"threat_detection"`
	RecoveryStrategies    RecoveryConfig        `yaml:"recovery_strategies" json:"recovery_strategies"`
	HealthChecks          HealthCheckConfig     `yaml:"health_checks" json:"health_checks"`
	Metrics               MetricsConfig         `yaml:"metrics" json:"metrics"`
	Alerting              AlertingConfig        `yaml:"alerting" json:"alerting"`
}

// PipelineConfig configures the self-healing pipeline
type PipelineConfig struct {
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	BufferSize          int           `yaml:"buffer_size" json:"buffer_size"`
	WorkerCount         int           `yaml:"worker_count" json:"worker_count"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`
	RetryAttempts       int           `yaml:"retry_attempts" json:"retry_attempts"`
	RetryBackoff        time.Duration `yaml:"retry_backoff" json:"retry_backoff"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	FailureThreshold    int           `yaml:"failure_threshold" json:"failure_threshold"`
	RecoveryThreshold   int           `yaml:"recovery_threshold" json:"recovery_threshold"`
	CircuitBreaker      CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// CircuitBreakerConfig configures circuit breakers
type CircuitBreakerConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	MaxRequests      uint32        `yaml:"max_requests" json:"max_requests"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold uint32        `yaml:"failure_threshold" json:"failure_threshold"`
	SuccessThreshold uint32        `yaml:"success_threshold" json:"success_threshold"`
}

// AnomalyConfig configures anomaly detection
type AnomalyConfig struct {
	Enabled                   bool          `yaml:"enabled" json:"enabled"`
	WindowSize                int           `yaml:"window_size" json:"window_size"`
	DetectionInterval         time.Duration `yaml:"detection_interval" json:"detection_interval"`
	Sensitivity               float64       `yaml:"sensitivity" json:"sensitivity"`
	MinDataPoints             int           `yaml:"min_data_points" json:"min_data_points"`
	BaselineUpdateInterval    time.Duration `yaml:"baseline_update_interval" json:"baseline_update_interval"`
	SeasonalityDetection      bool          `yaml:"seasonality_detection" json:"seasonality_detection"`
	AdaptiveThresholds        bool          `yaml:"adaptive_thresholds" json:"adaptive_thresholds"`
	ZScoreThreshold           float64       `yaml:"z_score_threshold" json:"z_score_threshold"`
	PercentileThreshold       float64       `yaml:"percentile_threshold" json:"percentile_threshold"`
	ExponentialSmoothingAlpha float64       `yaml:"exponential_smoothing_alpha" json:"exponential_smoothing_alpha"`
}

// AutoScalingConfig configures intelligent auto-scaling
type AutoScalingConfig struct {
	Enabled                 bool          `yaml:"enabled" json:"enabled"`
	MinWorkers              int           `yaml:"min_workers" json:"min_workers"`
	MaxWorkers              int           `yaml:"max_workers" json:"max_workers"`
	TargetCPUUtilization    float64       `yaml:"target_cpu_utilization" json:"target_cpu_utilization"`
	TargetMemoryUtilization float64       `yaml:"target_memory_utilization" json:"target_memory_utilization"`
	TargetQueueLength       int           `yaml:"target_queue_length" json:"target_queue_length"`
	CooldownPeriod          time.Duration `yaml:"cooldown_period" json:"cooldown_period"`
	ScaleUpThreshold        float64       `yaml:"scale_up_threshold" json:"scale_up_threshold"`
	ScaleDownThreshold      float64       `yaml:"scale_down_threshold" json:"scale_down_threshold"`
	PredictiveScaling       bool          `yaml:"predictive_scaling" json:"predictive_scaling"`
	SeasonalAdjustment      bool          `yaml:"seasonal_adjustment" json:"seasonal_adjustment"`
	AggressiveScaling       bool          `yaml:"aggressive_scaling" json:"aggressive_scaling"`
	EvaluationInterval      time.Duration `yaml:"evaluation_interval" json:"evaluation_interval"`
	PredictionWindow        time.Duration `yaml:"prediction_window" json:"prediction_window"`
}

// ErrorHandlingConfig configures advanced error handling
type ErrorHandlingConfig struct {
	Enabled                     bool          `yaml:"enabled" json:"enabled"`
	MaxErrorHistory             int           `yaml:"max_error_history" json:"max_error_history"`
	RecoveryAttempts            int           `yaml:"recovery_attempts" json:"recovery_attempts"`
	RecoveryBackoff             time.Duration `yaml:"recovery_backoff" json:"recovery_backoff"`
	ErrorThreshold              int           `yaml:"error_threshold" json:"error_threshold"`
	CircuitBreakerEnabled       bool          `yaml:"circuit_breaker_enabled" json:"circuit_breaker_enabled"`
	AutomaticRecovery           bool          `yaml:"automatic_recovery" json:"automatic_recovery"`
	DetailedStackTraces         bool          `yaml:"detailed_stack_traces" json:"detailed_stack_traces"`
	ErrorCorrelation            bool          `yaml:"error_correlation" json:"error_correlation"`
	PredictiveErrorDetection    bool          `yaml:"predictive_error_detection" json:"predictive_error_detection"`
	ErrorClassification         bool          `yaml:"error_classification" json:"error_classification"`
	ContextualLogging           bool          `yaml:"contextual_logging" json:"contextual_logging"`
}

// ThreatDetectionConfig configures security threat detection
type ThreatDetectionConfig struct {
	Enabled                  bool          `yaml:"enabled" json:"enabled"`
	MaxThreatHistory         int           `yaml:"max_threat_history" json:"max_threat_history"`
	AnomalyThreshold         float64       `yaml:"anomaly_threshold" json:"anomaly_threshold"`
	AutoBlacklistEnabled     bool          `yaml:"auto_blacklist_enabled" json:"auto_blacklist_enabled"`
	BlacklistDuration        time.Duration `yaml:"blacklist_duration" json:"blacklist_duration"`
	SuspiciousIPThreshold    int           `yaml:"suspicious_ip_threshold" json:"suspicious_ip_threshold"`
	RateLimitThreshold       int           `yaml:"rate_limit_threshold" json:"rate_limit_threshold"`
	RateLimitWindow          time.Duration `yaml:"rate_limit_window" json:"rate_limit_window"`
	SQLInjectionDetection    bool          `yaml:"sql_injection_detection" json:"sql_injection_detection"`
	XSSDetection             bool          `yaml:"xss_detection" json:"xss_detection"`
	BruteForceDetection      bool          `yaml:"brute_force_detection" json:"brute_force_detection"`
	DDoSDetection            bool          `yaml:"ddos_detection" json:"ddos_detection"`
	MalwareDetection         bool          `yaml:"malware_detection" json:"malware_detection"`
	DataLeakageDetection     bool          `yaml:"data_leakage_detection" json:"data_leakage_detection"`
	CryptographicValidation  bool          `yaml:"cryptographic_validation" json:"cryptographic_validation"`
	SupplyChainValidation    bool          `yaml:"supply_chain_validation" json:"supply_chain_validation"`
	RealTimeBlocking         bool          `yaml:"real_time_blocking" json:"real_time_blocking"`
	ThreatIntelligence       bool          `yaml:"threat_intelligence" json:"threat_intelligence"`
}

// RecoveryConfig configures recovery strategies
type RecoveryConfig struct {
	Enabled              bool                      `yaml:"enabled" json:"enabled"`
	Strategies           map[string]StrategyConfig `yaml:"strategies" json:"strategies"`
	DefaultMaxAttempts   int                       `yaml:"default_max_attempts" json:"default_max_attempts"`
	DefaultBackoff       time.Duration             `yaml:"default_backoff" json:"default_backoff"`
	DefaultTimeout       time.Duration             `yaml:"default_timeout" json:"default_timeout"`
	ParallelRecovery     bool                      `yaml:"parallel_recovery" json:"parallel_recovery"`
	RecoveryMetrics      bool                      `yaml:"recovery_metrics" json:"recovery_metrics"`
	RecoveryAlerting     bool                      `yaml:"recovery_alerting" json:"recovery_alerting"`
}

// StrategyConfig configures individual recovery strategies
type StrategyConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	MaxAttempts  int           `yaml:"max_attempts" json:"max_attempts"`
	Backoff      time.Duration `yaml:"backoff" json:"backoff"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
	Strategy     string        `yaml:"strategy" json:"strategy"`
	Parameters   map[string]interface{} `yaml:"parameters" json:"parameters"`
}

// HealthCheckConfig configures health checking
type HealthCheckConfig struct {
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	Interval            time.Duration `yaml:"interval" json:"interval"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold    int           `yaml:"failure_threshold" json:"failure_threshold"`
	SuccessThreshold    int           `yaml:"success_threshold" json:"success_threshold"`
	StartupGracePeriod  time.Duration `yaml:"startup_grace_period" json:"startup_grace_period"`
	Checks              map[string]CheckConfig `yaml:"checks" json:"checks"`
	DetailedReporting   bool          `yaml:"detailed_reporting" json:"detailed_reporting"`
	Alerting            bool          `yaml:"alerting" json:"alerting"`
}

// CheckConfig configures individual health checks
type CheckConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	Type        string        `yaml:"type" json:"type"`
	Endpoint    string        `yaml:"endpoint" json:"endpoint"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	Interval    time.Duration `yaml:"interval" json:"interval"`
	Parameters  map[string]interface{} `yaml:"parameters" json:"parameters"`
}

// SecurityConfig extends security configuration
type SecurityConfig struct {
	Enabled               bool                  `yaml:"enabled" json:"enabled"`
	TLS                   TLSConfig             `yaml:"tls" json:"tls"`
	Auth                  AuthConfig            `yaml:"auth" json:"auth"`
	RateLimit             RateLimitConfig       `yaml:"rate_limit" json:"rate_limit"`
	CORS                  CORSConfig            `yaml:"cors" json:"cors"`
	ThreatDetection       ThreatDetectionConfig `yaml:"threat_detection" json:"threat_detection"`
	Encryption            EncryptionConfig      `yaml:"encryption" json:"encryption"`
	AuditLogging          AuditConfig           `yaml:"audit_logging" json:"audit_logging"`
	VulnerabilityScanning VulnScanConfig        `yaml:"vulnerability_scanning" json:"vulnerability_scanning"`
}

// Additional security config types
type TLSConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	CertFile  string `yaml:"cert_file" json:"cert_file"`
	KeyFile   string `yaml:"key_file" json:"key_file"`
	MinVersion string `yaml:"min_version" json:"min_version"`
	CipherSuites []string `yaml:"cipher_suites" json:"cipher_suites"`
}

type AuthConfig struct {
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	JWT          JWTConfig         `yaml:"jwt" json:"jwt"`
	OAuth        OAuthConfig       `yaml:"oauth" json:"oauth"`
	APIKeys      APIKeyConfig      `yaml:"api_keys" json:"api_keys"`
	MFA          MFAConfig         `yaml:"mfa" json:"mfa"`
	SessionConfig SessionConfig    `yaml:"session" json:"session"`
}

type JWTConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	SecretKey      string        `yaml:"secret_key" json:"secret_key"`
	Issuer         string        `yaml:"issuer" json:"issuer"`
	Expiration     time.Duration `yaml:"expiration" json:"expiration"`
	RefreshEnabled bool          `yaml:"refresh_enabled" json:"refresh_enabled"`
	RefreshExpiration time.Duration `yaml:"refresh_expiration" json:"refresh_expiration"`
}

type OAuthConfig struct {
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	Providers    map[string]OAuthProvider `yaml:"providers" json:"providers"`
	CallbackURL  string            `yaml:"callback_url" json:"callback_url"`
	Scopes       []string          `yaml:"scopes" json:"scopes"`
}

type OAuthProvider struct {
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
	AuthURL      string `yaml:"auth_url" json:"auth_url"`
	TokenURL     string `yaml:"token_url" json:"token_url"`
	UserInfoURL  string `yaml:"user_info_url" json:"user_info_url"`
}

type APIKeyConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	HeaderName     string        `yaml:"header_name" json:"header_name"`
	Validation     string        `yaml:"validation" json:"validation"`
	Expiration     time.Duration `yaml:"expiration" json:"expiration"`
	RateLimit      int           `yaml:"rate_limit" json:"rate_limit"`
}

type MFAConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	Methods       []string `yaml:"methods" json:"methods"`
	TOTPIssuer    string   `yaml:"totp_issuer" json:"totp_issuer"`
	BackupCodes   bool     `yaml:"backup_codes" json:"backup_codes"`
	Enforcement   string   `yaml:"enforcement" json:"enforcement"`
}

type SessionConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	Secure         bool          `yaml:"secure" json:"secure"`
	HTTPOnly       bool          `yaml:"http_only" json:"http_only"`
	SameSite       string        `yaml:"same_site" json:"same_site"`
	CookieName     string        `yaml:"cookie_name" json:"cookie_name"`
}

type RateLimitConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	RequestsPerMin int          `yaml:"requests_per_min" json:"requests_per_min"`
	BurstSize     int           `yaml:"burst_size" json:"burst_size"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	Whitelist     []string      `yaml:"whitelist" json:"whitelist"`
	Blacklist     []string      `yaml:"blacklist" json:"blacklist"`
}

type CORSConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers" json:"allowed_headers"`
	ExposedHeaders []string `yaml:"exposed_headers" json:"exposed_headers"`
	AllowCredentials bool   `yaml:"allow_credentials" json:"allow_credentials"`
	MaxAge         int      `yaml:"max_age" json:"max_age"`
}

type EncryptionConfig struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	Algorithm     string `yaml:"algorithm" json:"algorithm"`
	KeySize       int    `yaml:"key_size" json:"key_size"`
	KeyDerivation string `yaml:"key_derivation" json:"key_derivation"`
	SaltSize      int    `yaml:"salt_size" json:"salt_size"`
	Iterations    int    `yaml:"iterations" json:"iterations"`
}

type AuditConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	LogFile         string   `yaml:"log_file" json:"log_file"`
	LogLevel        string   `yaml:"log_level" json:"log_level"`
	RotationSize    int64    `yaml:"rotation_size" json:"rotation_size"`
	RetentionDays   int      `yaml:"retention_days" json:"retention_days"`
	IncludeEvents   []string `yaml:"include_events" json:"include_events"`
	ExcludeEvents   []string `yaml:"exclude_events" json:"exclude_events"`
	SensitiveFields []string `yaml:"sensitive_fields" json:"sensitive_fields"`
}

type VulnScanConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Interval      time.Duration `yaml:"interval" json:"interval"`
	Scanners      []string      `yaml:"scanners" json:"scanners"`
	SeverityThreshold string   `yaml:"severity_threshold" json:"severity_threshold"`
	AutoRemediation bool        `yaml:"auto_remediation" json:"auto_remediation"`
	AlertOnFindings bool        `yaml:"alert_on_findings" json:"alert_on_findings"`
}

// MonitoringConfig configures monitoring and observability
type MonitoringConfig struct {
	Enabled         bool            `yaml:"enabled" json:"enabled"`
	Metrics         MetricsConfig   `yaml:"metrics" json:"metrics"`
	Tracing         TracingConfig   `yaml:"tracing" json:"tracing"`
	Logging         LoggingConfig   `yaml:"logging" json:"logging"`
	Alerting        AlertingConfig  `yaml:"alerting" json:"alerting"`
	Dashboards      DashboardConfig `yaml:"dashboards" json:"dashboards"`
	HealthChecks    HealthCheckConfig `yaml:"health_checks" json:"health_checks"`
}

// MetricsConfig configures metrics collection
type MetricsConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	CollectionInterval time.Duration `yaml:"collection_interval" json:"collection_interval"`
	RetentionPeriod  time.Duration `yaml:"retention_period" json:"retention_period"`
	Prometheus       PrometheusConfig `yaml:"prometheus" json:"prometheus"`
	InfluxDB         InfluxDBConfig   `yaml:"influxdb" json:"influxdb"`
	CustomMetrics    bool          `yaml:"custom_metrics" json:"custom_metrics"`
	SystemMetrics    bool          `yaml:"system_metrics" json:"system_metrics"`
	ApplicationMetrics bool        `yaml:"application_metrics" json:"application_metrics"`
	BusinessMetrics  bool          `yaml:"business_metrics" json:"business_metrics"`
}

type PrometheusConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Endpoint  string `yaml:"endpoint" json:"endpoint"`
	Port      int    `yaml:"port" json:"port"`
	Path      string `yaml:"path" json:"path"`
	PushGateway string `yaml:"push_gateway" json:"push_gateway"`
}

type InfluxDBConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	URL        string `yaml:"url" json:"url"`
	Database   string `yaml:"database" json:"database"`
	Username   string `yaml:"username" json:"username"`
	Password   string `yaml:"password" json:"password"`
	Retention  string `yaml:"retention" json:"retention"`
	Precision  string `yaml:"precision" json:"precision"`
}

// TracingConfig configures distributed tracing
type TracingConfig struct {
	Enabled      bool             `yaml:"enabled" json:"enabled"`
	Jaeger       JaegerConfig     `yaml:"jaeger" json:"jaeger"`
	Zipkin       ZipkinConfig     `yaml:"zipkin" json:"zipkin"`
	OTLP         OTLPConfig       `yaml:"otlp" json:"otlp"`
	SamplingRate float64          `yaml:"sampling_rate" json:"sampling_rate"`
	ServiceName  string           `yaml:"service_name" json:"service_name"`
	Attributes   map[string]string `yaml:"attributes" json:"attributes"`
}

type JaegerConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Endpoint  string `yaml:"endpoint" json:"endpoint"`
	AgentHost string `yaml:"agent_host" json:"agent_host"`
	AgentPort int    `yaml:"agent_port" json:"agent_port"`
}

type ZipkinConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
}

type OTLPConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Endpoint  string `yaml:"endpoint" json:"endpoint"`
	Insecure  bool   `yaml:"insecure" json:"insecure"`
	Headers   map[string]string `yaml:"headers" json:"headers"`
}

// LoggingConfig configures logging
type LoggingConfig struct {
	Level          string            `yaml:"level" json:"level"`
	Format         string            `yaml:"format" json:"format"`
	Output         []string          `yaml:"output" json:"output"`
	Rotation       RotationConfig    `yaml:"rotation" json:"rotation"`
	Structured     bool              `yaml:"structured" json:"structured"`
	SensitiveFields []string         `yaml:"sensitive_fields" json:"sensitive_fields"`
	Metadata       map[string]string `yaml:"metadata" json:"metadata"`
	AsyncLogging   bool              `yaml:"async_logging" json:"async_logging"`
	BufferSize     int               `yaml:"buffer_size" json:"buffer_size"`
	FlushInterval  time.Duration     `yaml:"flush_interval" json:"flush_interval"`
}

type RotationConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	MaxSize    int64  `yaml:"max_size" json:"max_size"`
	MaxAge     int    `yaml:"max_age" json:"max_age"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	Compress   bool   `yaml:"compress" json:"compress"`
}

// AlertingConfig configures alerting
type AlertingConfig struct {
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	Channels     map[string]AlertChannel `yaml:"channels" json:"channels"`
	Rules        []AlertRule       `yaml:"rules" json:"rules"`
	Escalation   EscalationConfig  `yaml:"escalation" json:"escalation"`
	Throttling   ThrottlingConfig  `yaml:"throttling" json:"throttling"`
	Maintenance  MaintenanceConfig `yaml:"maintenance" json:"maintenance"`
}

type AlertChannel struct {
	Type       string            `yaml:"type" json:"type"`
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	Endpoint   string            `yaml:"endpoint" json:"endpoint"`
	Credentials map[string]string `yaml:"credentials" json:"credentials"`
	Template   string            `yaml:"template" json:"template"`
	SeverityFilter []string       `yaml:"severity_filter" json:"severity_filter"`
}

type AlertRule struct {
	Name        string            `yaml:"name" json:"name"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Condition   string            `yaml:"condition" json:"condition"`
	Threshold   float64           `yaml:"threshold" json:"threshold"`
	Duration    time.Duration     `yaml:"duration" json:"duration"`
	Severity    string            `yaml:"severity" json:"severity"`
	Channels    []string          `yaml:"channels" json:"channels"`
	Labels      map[string]string `yaml:"labels" json:"labels"`
	Annotations map[string]string `yaml:"annotations" json:"annotations"`
}

type EscalationConfig struct {
	Enabled  bool              `yaml:"enabled" json:"enabled"`
	Levels   []EscalationLevel `yaml:"levels" json:"levels"`
	Timeout  time.Duration     `yaml:"timeout" json:"timeout"`
}

type EscalationLevel struct {
	Level    int           `yaml:"level" json:"level"`
	Delay    time.Duration `yaml:"delay" json:"delay"`
	Channels []string      `yaml:"channels" json:"channels"`
}

type ThrottlingConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	MaxAlerts   int           `yaml:"max_alerts" json:"max_alerts"`
	Window      time.Duration `yaml:"window" json:"window"`
	Grouping    bool          `yaml:"grouping" json:"grouping"`
	GroupBy     []string      `yaml:"group_by" json:"group_by"`
}

type MaintenanceConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Windows   []MaintenanceWindow `yaml:"windows" json:"windows"`
	Schedule  string            `yaml:"schedule" json:"schedule"`
	Timezone  string            `yaml:"timezone" json:"timezone"`
}

type MaintenanceWindow struct {
	Name     string    `yaml:"name" json:"name"`
	Start    time.Time `yaml:"start" json:"start"`
	End      time.Time `yaml:"end" json:"end"`
	Recurring bool     `yaml:"recurring" json:"recurring"`
	Pattern  string    `yaml:"pattern" json:"pattern"`
}

// DashboardConfig configures monitoring dashboards
type DashboardConfig struct {
	Enabled     bool                `yaml:"enabled" json:"enabled"`
	Grafana     GrafanaConfig       `yaml:"grafana" json:"grafana"`
	Kibana      KibanaConfig        `yaml:"kibana" json:"kibana"`
	Custom      []CustomDashboard   `yaml:"custom" json:"custom"`
	AutoRefresh time.Duration       `yaml:"auto_refresh" json:"auto_refresh"`
}

type GrafanaConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	URL      string `yaml:"url" json:"url"`
	APIKey   string `yaml:"api_key" json:"api_key"`
	OrgID    int    `yaml:"org_id" json:"org_id"`
}

type KibanaConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	URL     string `yaml:"url" json:"url"`
	Index   string `yaml:"index" json:"index"`
}

type CustomDashboard struct {
	Name     string            `yaml:"name" json:"name"`
	URL      string            `yaml:"url" json:"url"`
	Type     string            `yaml:"type" json:"type"`
	Config   map[string]interface{} `yaml:"config" json:"config"`
}

// FeatureConfig configures feature flags
type FeatureConfig struct {
	Flags              map[string]bool `yaml:"flags" json:"flags"`
	DynamicFlags       bool            `yaml:"dynamic_flags" json:"dynamic_flags"`
	RemoteConfig       bool            `yaml:"remote_config" json:"remote_config"`
	ConfigProvider     string          `yaml:"config_provider" json:"config_provider"`
	RefreshInterval    time.Duration   `yaml:"refresh_interval" json:"refresh_interval"`
	CacheEnabled       bool            `yaml:"cache_enabled" json:"cache_enabled"`
	CacheTTL           time.Duration   `yaml:"cache_ttl" json:"cache_ttl"`
}

// LimitsConfig configures various system limits
type LimitsConfig struct {
	MaxConnections      int           `yaml:"max_connections" json:"max_connections"`
	MaxRequestSize      int64         `yaml:"max_request_size" json:"max_request_size"`
	MaxResponseSize     int64         `yaml:"max_response_size" json:"max_response_size"`
	RequestTimeout      time.Duration `yaml:"request_timeout" json:"request_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	ReadHeaderTimeout   time.Duration `yaml:"read_header_timeout" json:"read_header_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout" json:"write_timeout"`
	MaxConcurrentRequests int         `yaml:"max_concurrent_requests" json:"max_concurrent_requests"`
	RateLimits          map[string]RateLimit `yaml:"rate_limits" json:"rate_limits"`
	CircuitBreakers     map[string]CircuitBreakerConfig `yaml:"circuit_breakers" json:"circuit_breakers"`
}

type RateLimit struct {
	Requests int           `yaml:"requests" json:"requests"`
	Window   time.Duration `yaml:"window" json:"window"`
	Burst    int           `yaml:"burst" json:"burst"`
}

// ConfigSubscriber interface for config change notifications
type ConfigSubscriber interface {
	OnConfigChange(oldConfig, newConfig *EnhancedConfig) error
	GetName() string
}

// NewDynamicConfigManager creates a new dynamic config manager
func NewDynamicConfigManager(configPath string, logger *logrus.Logger) (*DynamicConfigManager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}
	
	manager := &DynamicConfigManager{
		configPath:  configPath,
		watcher:     watcher,
		subscribers: make([]ConfigSubscriber, 0),
		logger:      logger,
		stopCh:      make(chan struct{}),
	}
	
	// Load initial configuration
	if err := manager.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load initial config: %w", err)
	}
	
	return manager, nil
}

// Start starts the dynamic config manager
func (dcm *DynamicConfigManager) Start(ctx context.Context) error {
	dcm.mutex.Lock()
	if dcm.running {
		dcm.mutex.Unlock()
		return fmt.Errorf("dynamic config manager is already running")
	}
	dcm.running = true
	dcm.mutex.Unlock()
	
	// Watch config file for changes
	if err := dcm.watcher.Add(filepath.Dir(dcm.configPath)); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}
	
	dcm.logger.Info("Starting dynamic config manager")
	
	// Start watch loop
	go dcm.watchLoop(ctx)
	
	return nil
}

// Stop stops the dynamic config manager
func (dcm *DynamicConfigManager) Stop() error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()
	
	if !dcm.running {
		return nil
	}
	
	dcm.running = false
	close(dcm.stopCh)
	
	if dcm.watcher != nil {
		dcm.watcher.Close()
	}
	
	dcm.logger.Info("Stopped dynamic config manager")
	return nil
}

// GetConfig returns the current configuration
func (dcm *DynamicConfigManager) GetConfig() *EnhancedConfig {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()
	
	// Return a copy to prevent external modifications
	configCopy := *dcm.config
	return &configCopy
}

// Subscribe adds a config change subscriber
func (dcm *DynamicConfigManager) Subscribe(subscriber ConfigSubscriber) {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()
	
	dcm.subscribers = append(dcm.subscribers, subscriber)
	dcm.logger.WithField("subscriber", subscriber.GetName()).Info("Config subscriber added")
}

// Unsubscribe removes a config change subscriber
func (dcm *DynamicConfigManager) Unsubscribe(subscriberName string) {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()
	
	for i, subscriber := range dcm.subscribers {
		if subscriber.GetName() == subscriberName {
			dcm.subscribers = append(dcm.subscribers[:i], dcm.subscribers[i+1:]...)
			dcm.logger.WithField("subscriber", subscriberName).Info("Config subscriber removed")
			return
		}
	}
}

// UpdateConfig updates the configuration programmatically
func (dcm *DynamicConfigManager) UpdateConfig(updater func(*EnhancedConfig) error) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()
	
	oldConfig := *dcm.config
	newConfig := *dcm.config
	
	if err := updater(&newConfig); err != nil {
		return fmt.Errorf("config update failed: %w", err)
	}
	
	newConfig.UpdatedAt = time.Now()
	
	// Validate new configuration
	if err := dcm.validateConfig(&newConfig); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	
	// Apply new configuration
	dcm.config = &newConfig
	
	// Notify subscribers
	go dcm.notifySubscribers(&oldConfig, &newConfig)
	
	// Optionally save to file
	if err := dcm.saveConfig(); err != nil {
		dcm.logger.WithError(err).Warn("Failed to save updated config to file")
	}
	
	return nil
}

// ReloadConfig forces a reload of the configuration from file
func (dcm *DynamicConfigManager) ReloadConfig() error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()
	
	oldConfig := *dcm.config
	
	if err := dcm.loadConfig(); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	
	// Notify subscribers of the change
	go dcm.notifySubscribers(&oldConfig, dcm.config)
	
	return nil
}

// loadConfig loads configuration from file
func (dcm *DynamicConfigManager) loadConfig() error {
	data, err := ioutil.ReadFile(dcm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config EnhancedConfig
	
	// Determine file format and parse accordingly
	ext := filepath.Ext(dcm.configPath)
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
	
	// Validate configuration
	if err := dcm.validateConfig(&config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	
	// Apply defaults
	dcm.applyDefaults(&config)
	
	dcm.config = &config
	dcm.logger.Info("Configuration loaded successfully")
	
	return nil
}

// saveConfig saves the current configuration to file
func (dcm *DynamicConfigManager) saveConfig() error {
	ext := filepath.Ext(dcm.configPath)
	var data []byte
	var err error
	
	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(dcm.config)
	case ".json":
		data, err = json.MarshalIndent(dcm.config, "", "  ")
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := ioutil.WriteFile(dcm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// validateConfig validates the configuration
func (dcm *DynamicConfigManager) validateConfig(config *EnhancedConfig) error {
	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}
	
	// Validate self-healing configuration
	if config.SelfHealing.Enabled {
		if config.SelfHealing.Pipeline.WorkerCount < 1 {
			return fmt.Errorf("pipeline worker count must be at least 1")
		}
		if config.SelfHealing.AutoScaling.MinWorkers > config.SelfHealing.AutoScaling.MaxWorkers {
			return fmt.Errorf("min workers cannot be greater than max workers")
		}
	}
	
	// Validate monitoring configuration
	if config.Monitoring.Enabled {
		if config.Monitoring.Metrics.Prometheus.Enabled && config.Monitoring.Metrics.Prometheus.Port <= 0 {
			return fmt.Errorf("invalid Prometheus port")
		}
	}
	
	// Validate security configuration
	if config.Security.Enabled {
		if config.Security.Auth.JWT.Enabled && config.Security.Auth.JWT.SecretKey == "" {
			return fmt.Errorf("JWT secret key is required when JWT is enabled")
		}
	}
	
	return nil
}

// applyDefaults applies default values to the configuration
func (dcm *DynamicConfigManager) applyDefaults(config *EnhancedConfig) {
	// Apply server defaults
	if config.Server.Port == 0 {
		config.Server.Port = 8080
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 30 * time.Second
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 30 * time.Second
	}
	
	// Apply self-healing defaults
	if config.SelfHealing.Enabled {
		if config.SelfHealing.Pipeline.BufferSize == 0 {
			config.SelfHealing.Pipeline.BufferSize = 1000
		}
		if config.SelfHealing.Pipeline.WorkerCount == 0 {
			config.SelfHealing.Pipeline.WorkerCount = 10
		}
		if config.SelfHealing.Pipeline.Timeout == 0 {
			config.SelfHealing.Pipeline.Timeout = 30 * time.Second
		}
	}
	
	// Apply monitoring defaults
	if config.Monitoring.Enabled {
		if config.Monitoring.Metrics.CollectionInterval == 0 {
			config.Monitoring.Metrics.CollectionInterval = 30 * time.Second
		}
		if config.Monitoring.Metrics.Prometheus.Port == 0 {
			config.Monitoring.Metrics.Prometheus.Port = 9090
		}
	}
	
	// Apply logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}
	
	// Set version and timestamp
	if config.Version == "" {
		config.Version = "1.0.0"
	}
	config.UpdatedAt = time.Now()
}

// watchLoop watches for configuration file changes
func (dcm *DynamicConfigManager) watchLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-dcm.watcher.Events:
			if !ok {
				return
			}
			
			if event.Op&fsnotify.Write == fsnotify.Write {
				if filepath.Base(event.Name) == filepath.Base(dcm.configPath) {
					dcm.logger.Info("Configuration file changed, reloading...")
					
					// Add a small delay to ensure file write is complete
					time.Sleep(100 * time.Millisecond)
					
					if err := dcm.ReloadConfig(); err != nil {
						dcm.logger.WithError(err).Error("Failed to reload configuration")
					}
				}
			}
			
		case err, ok := <-dcm.watcher.Errors:
			if !ok {
				return
			}
			dcm.logger.WithError(err).Error("File watcher error")
			
		case <-dcm.stopCh:
			return
			
		case <-ctx.Done():
			return
		}
	}
}

// notifySubscribers notifies all subscribers of configuration changes
func (dcm *DynamicConfigManager) notifySubscribers(oldConfig, newConfig *EnhancedConfig) {
	for _, subscriber := range dcm.subscribers {
		go func(sub ConfigSubscriber) {
			if err := sub.OnConfigChange(oldConfig, newConfig); err != nil {
				dcm.logger.WithFields(logrus.Fields{
					"subscriber": sub.GetName(),
					"error":      err.Error(),
				}).Error("Config subscriber notification failed")
			} else {
				dcm.logger.WithField("subscriber", sub.GetName()).Debug("Config subscriber notified")
			}
		}(subscriber)
	}
}

// GetConfigSection returns a specific section of the configuration
func (dcm *DynamicConfigManager) GetConfigSection(section string) (interface{}, error) {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()
	
	switch section {
	case "server":
		return dcm.config.Server, nil
	case "database":
		return dcm.config.Database, nil
	case "self_healing":
		return dcm.config.SelfHealing, nil
	case "security":
		return dcm.config.Security, nil
	case "monitoring":
		return dcm.config.Monitoring, nil
	case "logging":
		return dcm.config.Logging, nil
	case "features":
		return dcm.config.Features, nil
	case "limits":
		return dcm.config.Limits, nil
	default:
		return nil, fmt.Errorf("unknown config section: %s", section)
	}
}

// UpdateConfigSection updates a specific section of the configuration
func (dcm *DynamicConfigManager) UpdateConfigSection(section string, value interface{}) error {
	return dcm.UpdateConfig(func(config *EnhancedConfig) error {
		switch section {
		case "self_healing":
			if shConfig, ok := value.(SelfHealingConfig); ok {
				config.SelfHealing = shConfig
			} else {
				return fmt.Errorf("invalid type for self_healing config")
			}
		case "security":
			if secConfig, ok := value.(SecurityConfig); ok {
				config.Security = secConfig
			} else {
				return fmt.Errorf("invalid type for security config")
			}
		case "monitoring":
			if monConfig, ok := value.(MonitoringConfig); ok {
				config.Monitoring = monConfig
			} else {
				return fmt.Errorf("invalid type for monitoring config")
			}
		default:
			return fmt.Errorf("unsupported config section for update: %s", section)
		}
		return nil
	})
}

// GetFeatureFlag returns the value of a feature flag
func (dcm *DynamicConfigManager) GetFeatureFlag(flagName string) bool {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()
	
	if dcm.config.Features.Flags == nil {
		return false
	}
	
	return dcm.config.Features.Flags[flagName]
}

// SetFeatureFlag sets the value of a feature flag
func (dcm *DynamicConfigManager) SetFeatureFlag(flagName string, value bool) error {
	return dcm.UpdateConfig(func(config *EnhancedConfig) error {
		if config.Features.Flags == nil {
			config.Features.Flags = make(map[string]bool)
		}
		config.Features.Flags[flagName] = value
		return nil
	})
}

// ExportConfig exports the current configuration to a file
func (dcm *DynamicConfigManager) ExportConfig(exportPath string) error {
	dcm.mutex.RLock()
	config := *dcm.config
	dcm.mutex.RUnlock()
	
	ext := filepath.Ext(exportPath)
	var data []byte
	var err error
	
	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(&config)
	case ".json":
		data, err = json.MarshalIndent(&config, "", "  ")
	default:
		return fmt.Errorf("unsupported export format: %s", ext)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := ioutil.WriteFile(exportPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}
	
	dcm.logger.WithField("export_path", exportPath).Info("Configuration exported")
	return nil
}

// GetConfigHistory returns configuration change history (if implemented)
func (dcm *DynamicConfigManager) GetConfigHistory() []ConfigChange {
	// This would be implemented with a proper configuration history store
	return []ConfigChange{}
}

// ConfigChange represents a configuration change event
type ConfigChange struct {
	Timestamp   time.Time   `json:"timestamp"`
	Section     string      `json:"section"`
	OldValue    interface{} `json:"old_value"`
	NewValue    interface{} `json:"new_value"`
	ChangedBy   string      `json:"changed_by"`
	Reason      string      `json:"reason"`
}
