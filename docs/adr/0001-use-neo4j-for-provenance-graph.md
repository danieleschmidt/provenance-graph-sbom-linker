# ADR-0001: Use Neo4j for Provenance Graph Storage

## Status
Accepted

## Context
The provenance graph SBOM linker needs to store complex relationships between source code commits, build artifacts, container images, dependencies, and deployments. The data model is inherently graph-based with many-to-many relationships and the need for efficient traversal queries.

## Decision
We will use Neo4j as the primary database for storing the provenance graph.

## Alternatives Considered

### 1. Relational Database (PostgreSQL)
- **Pros**: Mature ecosystem, ACID guarantees, familiar SQL
- **Cons**: Complex joins for graph traversal, poor performance for multi-hop queries, schema rigidity

### 2. Document Database (MongoDB)
- **Pros**: Flexible schema, good for nested data
- **Cons**: No native graph operations, complex relationship queries, limited consistency

### 3. Graph Database (ArangoDB)
- **Pros**: Multi-model (document + graph), good performance
- **Cons**: Smaller ecosystem, less enterprise adoption

### 4. Graph Database (Amazon Neptune)
- **Pros**: Managed service, supports both Gremlin and SPARQL
- **Cons**: Vendor lock-in, limited query language flexibility

## Rationale

### Why Neo4j:

1. **Native Graph Processing**: Optimized for graph traversal with constant-time relationship navigation
2. **Cypher Query Language**: Intuitive, SQL-like syntax for graph queries
3. **ACID Compliance**: Full ACID transactions for data consistency
4. **Mature Ecosystem**: Extensive tooling, drivers, and community support
5. **Scalability**: Supports clustering and read replicas for high availability
6. **Performance**: Excellent performance for complex graph queries and pattern matching
7. **Security**: Enterprise-grade security features including RBAC and encryption

### Use Cases Well-Suited for Neo4j:

- **Provenance Tracking**: Find all artifacts derived from a specific commit
- **Impact Analysis**: Determine blast radius of a vulnerability across the supply chain
- **Compliance Verification**: Validate complete audit trail from source to deployment
- **Dependency Analysis**: Traverse complex dependency trees efficiently
- **Pattern Detection**: Identify suspicious patterns in build and deployment flows

## Implementation Details

### Schema Design
```cypher
// Node Labels
:Source, :Build, :Artifact, :SBOM, :Vulnerability, :Deployment, :Signature

// Relationship Types
:BUILT_INTO, :PRODUCES, :HAS_SBOM, :CONTAINS, :VULNERABLE_TO, :SIGNED_BY, :DEPLOYED_TO
```

### Performance Considerations
- Index on frequently queried properties (commit hash, artifact name, CVE ID)
- Use relationship direction and types for query optimization
- Implement connection pooling for concurrent access
- Configure appropriate memory settings for graph algorithms

### High Availability
- Deploy Neo4j cluster with 3 core servers and 2 read replicas
- Use Kubernetes StatefulSets for persistent storage
- Implement automated backup and recovery procedures
- Configure monitoring and alerting for cluster health

## Consequences

### Positive
- Excellent query performance for graph operations
- Intuitive data modeling matching the problem domain
- Rich ecosystem and tooling support
- Built-in clustering and HA capabilities
- Strong consistency guarantees

### Negative
- Learning curve for Cypher query language
- Higher memory requirements compared to relational databases
- Potential vendor lock-in to Neo4j ecosystem
- Additional operational complexity for cluster management

### Neutral
- Need to develop Neo4j expertise in the team
- Requires careful capacity planning for memory usage
- Must implement proper backup and recovery procedures

## Compliance and Security
- Neo4j Enterprise supports encryption at rest and in transit
- RBAC capabilities align with security requirements
- Audit logging available for compliance needs
- Clustering supports data residency requirements

## Success Metrics
- Query response time <500ms for typical provenance queries
- Support for >100,000 nodes and >1M relationships
- 99.9% availability with clustering configuration
- Zero data loss during planned maintenance

## Review Date
This decision will be reviewed in 6 months (August 2025) or when significant new requirements emerge.

## Related Decisions
- ADR-0002: API Design Patterns
- ADR-0003: Authentication and Authorization Strategy