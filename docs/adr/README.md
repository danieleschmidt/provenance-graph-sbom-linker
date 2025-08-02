# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for the Provenance Graph SBOM Linker project.

## About ADRs

Architecture Decision Records (ADRs) capture important architectural decisions made during the project development. Each ADR documents the context, decision, and consequences of a particular architectural choice.

## ADR Template

Use the following template when creating new ADRs:

```markdown
# ADR-NNNN: [Title]

## Status
[Proposed | Accepted | Deprecated | Replaced by ADR-XXXX]

## Context
[Describe the problem or situation requiring a decision]

## Decision
[State the decision made]

## Consequences
[Describe the consequences of the decision, both positive and negative]

## Alternatives Considered
[List alternative solutions that were considered]

## Related Decisions
[Reference related ADRs if any]
```

## Existing ADRs

- [ADR-0001: Use Neo4j for Provenance Graph](0001-use-neo4j-for-provenance-graph.md)

## Process

1. Create a new ADR file with the next sequential number
2. Use the template above as a starting point
3. Submit for review via pull request
4. Update status to "Accepted" once approved
5. Update related documentation as needed