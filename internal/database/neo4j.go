package database

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/your-org/provenance-graph-sbom-linker/internal/config"
)

type Neo4jDB struct {
	driver neo4j.DriverWithContext
}

func NewNeo4jConnection(cfg config.DatabaseConfig) (*Neo4jDB, error) {
	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	ctx := context.Background()
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	return &Neo4jDB{driver: driver}, nil
}

func (db *Neo4jDB) Close() error {
	ctx := context.Background()
	return db.driver.Close(ctx)
}

func (db *Neo4jDB) GetSession() neo4j.SessionWithContext {
	return db.driver.NewSession(context.Background(), neo4j.SessionConfig{})
}

func (db *Neo4jDB) ExecuteQuery(ctx context.Context, cypher string, params map[string]interface{}) (*neo4j.EagerResult, error) {
	return neo4j.ExecuteQuery(ctx, db.driver, cypher, params, neo4j.EagerResultTransformer)
}