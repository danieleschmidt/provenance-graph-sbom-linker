package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestConfig holds configuration for test environment
type TestConfig struct {
	Neo4jURI      string
	Neo4jUsername string
	Neo4jPassword string
	RedisURL      string
	TestTimeout   time.Duration
}

// DefaultTestConfig returns default configuration for tests
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		Neo4jURI:      getEnvOrDefault("TEST_NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUsername: getEnvOrDefault("TEST_NEO4J_USERNAME", "neo4j"),
		Neo4jPassword: getEnvOrDefault("TEST_NEO4J_PASSWORD", "devpassword"),
		RedisURL:      getEnvOrDefault("TEST_REDIS_URL", "redis://localhost:6379/1"),
		TestTimeout:   30 * time.Second,
	}
}

// TestDB represents a test database connection
type TestDB struct {
	driver neo4j.DriverWithContext
	config *TestConfig
}

// THelper interface for both testing.T and testing.B
type THelper interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	FailNow()
}

// NewTestDB creates a new test database connection
func NewTestDB(t THelper) *TestDB {
	t.Helper()
	
	config := DefaultTestConfig()
	
	driver, err := neo4j.NewDriverWithContext(
		config.Neo4jURI,
		neo4j.BasicAuth(config.Neo4jUsername, config.Neo4jPassword, ""),
	)
	require.NoError(t, err, "Failed to create Neo4j test driver")
	
	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)
	defer cancel()
	
	err = driver.VerifyConnectivity(ctx)
	require.NoError(t, err, "Failed to connect to Neo4j test database")
	
	db := &TestDB{
		driver: driver,
		config: config,
	}
	
	// Setup cleanup
	t.Cleanup(func() {
		db.Close()
	})
	
	// Clear test data
	db.clearTestData(t)
	
	return db
}

// Close closes the database connection
func (db *TestDB) Close() {
	if db.driver != nil {
		db.driver.Close(context.Background())
	}
}

// Session creates a new database session
func (db *TestDB) Session(ctx context.Context) neo4j.SessionWithContext {
	return db.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: "neo4j",
	})
}

// clearTestData removes all test data from the database
func (db *TestDB) clearTestData(t THelper) {
	t.Helper()
	
	ctx, cancel := context.WithTimeout(context.Background(), db.config.TestTimeout)
	defer cancel()
	
	session := db.Session(ctx)
	defer session.Close(ctx)
	
	// Clear all nodes and relationships with test labels
	_, err := session.Run(ctx, `
		MATCH (n)
		WHERE any(label IN labels(n) WHERE label STARTS WITH 'Test')
		DETACH DELETE n
	`, nil)
	require.NoError(t, err, "Failed to clear test data")
}

// ExecuteQuery executes a Cypher query and returns the result
func (db *TestDB) ExecuteQuery(ctx context.Context, query string, parameters map[string]any) (neo4j.ResultWithContext, error) {
	session := db.Session(ctx)
	defer session.Close(ctx)
	
	return session.Run(ctx, query, parameters)
}

// TestCache represents a test Redis cache connection
type TestCache struct {
	client *redis.Client
	config *TestConfig
}

// NewTestCache creates a new test cache connection
func NewTestCache(t *testing.T) *TestCache {
	t.Helper()
	
	config := DefaultTestConfig()
	
	opts, err := redis.ParseURL(config.RedisURL)
	require.NoError(t, err, "Failed to parse Redis URL")
	
	client := redis.NewClient(opts)
	
	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)
	defer cancel()
	
	_, err = client.Ping(ctx).Result()
	require.NoError(t, err, "Failed to connect to Redis test cache")
	
	cache := &TestCache{
		client: client,
		config: config,
	}
	
	// Setup cleanup
	t.Cleanup(func() {
		cache.Close()
	})
	
	// Clear test data
	cache.clearTestData(t)
	
	return cache
}

// Close closes the cache connection
func (cache *TestCache) Close() {
	if cache.client != nil {
		cache.client.Close()
	}
}

// Client returns the Redis client
func (cache *TestCache) Client() *redis.Client {
	return cache.client
}

// clearTestData removes all test data from the cache
func (cache *TestCache) clearTestData(t *testing.T) {
	t.Helper()
	
	ctx, cancel := context.WithTimeout(context.Background(), cache.config.TestTimeout)
	defer cancel()
	
	// Clear all keys with test prefix
	keys, err := cache.client.Keys(ctx, "test:*").Result()
	require.NoError(t, err, "Failed to list test keys")
	
	if len(keys) > 0 {
		_, err = cache.client.Del(ctx, keys...).Result()
		require.NoError(t, err, "Failed to delete test keys")
	}
}

// RunWithSetup runs tests with setup and teardown functions
func RunWithSetup(m *testing.M, setup func(), teardown func()) int {
	// Setup
	if setup != nil {
		setup()
	}
	
	// Run tests
	code := m.Run()
	
	// Teardown
	if teardown != nil {
		teardown()
	}
	
	return code
}

// SkipIfShort skips the test if running in short mode
func SkipIfShort(t *testing.T, reason string) {
	t.Helper()
	
	if testing.Short() {
		t.Skipf("Skipping test in short mode: %s", reason)
	}
}

// SkipIfNotIntegration skips the test if not running integration tests
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test (set INTEGRATION_TEST=true to run)")
	}
}

// SkipIfNotE2E skips the test if not running end-to-end tests
func SkipIfNotE2E(t *testing.T) {
	t.Helper()
	
	if os.Getenv("E2E_TEST") != "true" {
		t.Skip("Skipping E2E test (set E2E_TEST=true to run)")
	}
}

// RequireEnvVar requires an environment variable to be set
func RequireEnvVar(t *testing.T, name string) string {
	t.Helper()
	
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("Required environment variable %s is not set", name)
	}
	
	return value
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(name, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}

// WaitForCondition waits for a condition to be true or timeout
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	t.Helper()
	
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	
	for {
		select {
		case <-ticker.C:
			if condition() {
				return
			}
		case <-timer.C:
			t.Fatalf("Timeout waiting for condition: %s", message)
		}
	}
}

// RandomString generates a random string for test data
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// TestNamespace generates a unique namespace for test isolation
func TestNamespace(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test_%s_%d", t.Name(), time.Now().UnixNano())
}