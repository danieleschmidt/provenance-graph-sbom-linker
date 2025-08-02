# ADR-0002: Event-Driven Architecture for Provenance Tracking

## Status
Accepted

## Context
The provenance graph system needs to handle high-throughput ingestion of build events, artifact updates, and signature verification while maintaining real-time query capabilities. Traditional synchronous processing patterns would create bottlenecks and reduce system reliability.

## Decision
We will implement an event-driven architecture using asynchronous message processing for all provenance data ingestion, while maintaining synchronous APIs for queries and critical operations.

### Components
- **Event Bus**: Redis Streams for reliable message delivery
- **Event Producers**: CLI tools, CI/CD integrations, API endpoints
- **Event Consumers**: Specialized workers for different event types
- **Event Store**: Immutable event log in Neo4j for audit trails

### Event Types
1. `source.commit.created` - New commit detected
2. `build.started` / `build.completed` - Build lifecycle events
3. `artifact.created` / `artifact.signed` - Artifact lifecycle
4. `deployment.created` / `deployment.verified` - Deployment events
5. `vulnerability.detected` - Security scan results

## Consequences

### Positive
- **Scalability**: Independent scaling of event producers and consumers
- **Reliability**: Built-in retry mechanisms and dead letter queues
- **Auditability**: Complete event history for compliance
- **Decoupling**: Services can evolve independently
- **Performance**: Asynchronous processing doesn't block user operations

### Negative
- **Complexity**: More moving parts to monitor and debug
- **Eventual Consistency**: Some queries may not reflect latest events immediately
- **Event Ordering**: Need careful handling of out-of-order events

### Mitigation Strategies
- Implement comprehensive monitoring and alerting
- Use event versioning for backward compatibility
- Design idempotent event handlers
- Implement event replay capabilities for recovery

## Implementation Notes
- Use Redis Streams consumer groups for load balancing
- Implement exponential backoff for failed event processing
- Store event metadata (correlation IDs, timestamps) for tracing
- Use structured logging with event correlation

## Related ADRs
- ADR-0001: Use Neo4j for Provenance Graph
- ADR-0003: Cryptographic Verification Strategy (planned)