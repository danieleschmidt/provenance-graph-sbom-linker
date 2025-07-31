package config

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Server.Port)
	}

	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("Expected default read timeout 30s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Database.URI != "bolt://localhost:7687" {
		t.Errorf("Expected default Neo4j URI, got %s", cfg.Database.URI)
	}

	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default log level 'info', got %s", cfg.Logging.Level)
	}
}