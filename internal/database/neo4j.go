package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
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

	db := &Neo4jDB{driver: driver}
	if err := db.InitializeSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
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

func (db *Neo4jDB) InitializeSchema(ctx context.Context) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	schemaQueries := []string{
		"CREATE CONSTRAINT artifact_id IF NOT EXISTS FOR (a:Artifact) REQUIRE a.id IS UNIQUE",
		"CREATE CONSTRAINT source_id IF NOT EXISTS FOR (s:Source) REQUIRE s.id IS UNIQUE",
		"CREATE CONSTRAINT component_id IF NOT EXISTS FOR (c:Component) REQUIRE c.id IS UNIQUE",
		"CREATE INDEX artifact_name_version IF NOT EXISTS FOR (a:Artifact) ON (a.name, a.version)",
		"CREATE INDEX source_url IF NOT EXISTS FOR (s:Source) ON (s.url)",
		"CREATE INDEX component_name IF NOT EXISTS FOR (c:Component) ON (c.name)",
	}

	for _, query := range schemaQueries {
		if _, err := session.Run(ctx, query, nil); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

func (db *Neo4jDB) CreateArtifact(ctx context.Context, artifact *types.Artifact) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		CREATE (a:Artifact {
			id: $id,
			name: $name,
			version: $version,
			type: $type,
			hash: $hash,
			size: $size,
			created_at: $created_at,
			updated_at: $updated_at
		})
		RETURN a
	`

	params := map[string]interface{}{
		"id":         artifact.ID.String(),
		"name":       artifact.Name,
		"version":    artifact.Version,
		"type":       string(artifact.Type),
		"hash":       artifact.Hash,
		"size":       artifact.Size,
		"created_at": artifact.CreatedAt.Unix(),
		"updated_at": artifact.UpdatedAt.Unix(),
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (db *Neo4jDB) GetArtifact(ctx context.Context, id string) (*types.Artifact, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		MATCH (a:Artifact {id: $id})
		RETURN a.id, a.name, a.version, a.type, a.hash, a.size, a.created_at, a.updated_at
	`

	result, err := session.Run(ctx, query, map[string]interface{}{"id": id})
	if err != nil {
		return nil, err
	}

	if result.Next(ctx) {
		record := result.Record()
		artifact := &types.Artifact{}
		
		if idStr, ok := record.Get("a.id"); ok {
			artifact.ID = parseUUID(idStr.(string))
		}
		if name, ok := record.Get("a.name"); ok {
			artifact.Name = name.(string)
		}
		if version, ok := record.Get("a.version"); ok {
			artifact.Version = version.(string)
		}
		if artifactType, ok := record.Get("a.type"); ok {
			artifact.Type = types.ArtifactType(artifactType.(string))
		}
		if hash, ok := record.Get("a.hash"); ok {
			artifact.Hash = hash.(string)
		}
		if size, ok := record.Get("a.size"); ok {
			artifact.Size = size.(int64)
		}
		if createdAtUnix, ok := record.Get("a.created_at"); ok {
			artifact.CreatedAt = time.Unix(createdAtUnix.(int64), 0)
		}
		if updatedAtUnix, ok := record.Get("a.updated_at"); ok {
			artifact.UpdatedAt = time.Unix(updatedAtUnix.(int64), 0)
		}
		
		return artifact, nil
	}

	return nil, fmt.Errorf("artifact not found")
}

func (db *Neo4jDB) CreateProvenanceLink(ctx context.Context, fromID, toID string, linkType string) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := fmt.Sprintf(`
		MATCH (from {id: $fromID})
		MATCH (to {id: $toID})
		CREATE (from)-[r:%s]->(to)
		RETURN r
	`, linkType)

	params := map[string]interface{}{
		"fromID": fromID,
		"toID":   toID,
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (db *Neo4jDB) CreateSource(ctx context.Context, source *types.Source) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		CREATE (s:Source {
			id: $id,
			type: $type,
			url: $url,
			branch: $branch,
			commit_hash: $commit_hash,
			tag: $tag,
			created_at: $created_at
		})
		RETURN s
	`

	params := map[string]interface{}{
		"id":          source.ID.String(),
		"type":        string(source.Type),
		"url":         source.URL,
		"branch":      source.Branch,
		"commit_hash": source.CommitHash,
		"tag":         source.Tag,
		"created_at":  source.CreatedAt.Unix(),
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (db *Neo4jDB) CreateBuildEvent(ctx context.Context, build *types.BuildEvent) error {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		CREATE (b:Build {
			id: $id,
			source_ref: $source_ref,
			commit_hash: $commit_hash,
			build_id: $build_id,
			build_system: $build_system,
			build_url: $build_url,
			timestamp: $timestamp
		})
		RETURN b
	`

	params := map[string]interface{}{
		"id":           build.ID.String(),
		"source_ref":   build.SourceRef,
		"commit_hash":  build.CommitHash,
		"build_id":     build.BuildID,
		"build_system": build.BuildSystem,
		"build_url":    build.BuildURL,
		"timestamp":    build.Timestamp.Unix(),
	}

	_, err := session.Run(ctx, query, params)
	return err
}

func (db *Neo4jDB) GetProvenanceGraph(ctx context.Context, artifactID string, depth int) (*types.ProvenanceGraph, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		MATCH path = (a:Artifact {id: $artifactID})-[*0..` + fmt.Sprintf("%d", depth) + `]-()
		RETURN nodes(path) as nodes, relationships(path) as edges
	`

	result, err := session.Run(ctx, query, map[string]interface{}{"artifactID": artifactID})
	if err != nil {
		return nil, err
	}

	graph := &types.ProvenanceGraph{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Metadata:  make(map[string]string),
		Nodes:     []types.Node{},
		Edges:     []types.Edge{},
	}

	for result.Next(ctx) {
		record := result.Record()
		if nodes, ok := record.Get("nodes"); ok {
			for _, node := range nodes.([]interface{}) {
				n := node.(neo4j.Node)
				graph.Nodes = append(graph.Nodes, types.Node{
					ID:       n.Props["id"].(string),
					Type:     types.NodeType(n.Labels[0]),
					Label:    fmt.Sprintf("%s", n.Props["name"]),
					Data:     n.Props,
					Metadata: make(map[string]string),
				})
			}
		}
	}

	return graph, nil
}

func parseUUID(s string) uuid.UUID {
	if uid, err := uuid.Parse(s); err == nil {
		return uid
	}
	return uuid.UUID{}
}