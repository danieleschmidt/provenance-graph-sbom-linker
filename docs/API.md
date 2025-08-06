# API Documentation

The Provenance Graph SBOM Linker provides a comprehensive REST API for managing software supply chain provenance data.

## Base URL

```
https://api.your-domain.com/api/v1
```

## Authentication

The API supports multiple authentication methods:

### API Key Authentication

Include the API key in the request header:

```http
X-API-Key: pk_your_api_key_here
```

Or as a query parameter:

```http
GET /api/v1/artifacts?api_key=pk_your_api_key_here
```

### JWT Authentication

Include the JWT token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Core Resources

### Artifacts

Artifacts represent build outputs, containers, binaries, or any trackable software components.

#### Create Artifact

```http
POST /api/v1/artifacts
Content-Type: application/json

{
  "name": "my-application",
  "version": "1.2.0",
  "type": "container",
  "hash": "sha256:abc123...",
  "size": 1048576,
  "metadata": {
    "build_system": "github-actions",
    "environment": "production"
  }
}
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "my-application",
  "version": "1.2.0",
  "type": "container",
  "hash": "sha256:abc123...",
  "size": 1048576,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "metadata": {
    "build_system": "github-actions",
    "environment": "production"
  },
  "signatures": [],
  "dependencies": [],
  "attestations": []
}
```

#### Get Artifact

```http
GET /api/v1/artifacts/{id}
```

#### List Artifacts

```http
GET /api/v1/artifacts?limit=50&offset=0&type=container
```

**Query Parameters:**

- `limit` (integer): Number of results to return (max 1000, default 50)
- `offset` (integer): Number of results to skip (default 0)
- `type` (string): Filter by artifact type
- `name` (string): Filter by artifact name
- `version` (string): Filter by version

#### Update Artifact

```http
PUT /api/v1/artifacts/{id}
Content-Type: application/json

{
  "metadata": {
    "updated_field": "new_value"
  }
}
```

#### Delete Artifact

```http
DELETE /api/v1/artifacts/{id}
```

### Provenance

Provenance tracks the relationships and history of artifacts throughout the software supply chain.

#### Get Provenance Graph

```http
GET /api/v1/provenance/{artifact_id}
```

**Query Parameters:**

- `depth` (integer): How many levels deep to traverse (default 5, max 20)
- `include_sbom` (boolean): Include SBOM data in response
- `include_signatures` (boolean): Include signature data
- `format` (string): Response format ('json', 'graphml', 'cypher')

**Response:**

```json
{
  "id": "graph-550e8400-e29b-41d4-a716-446655440000",
  "nodes": [
    {
      "id": "artifact-123",
      "type": "artifact",
      "label": "my-application:1.2.0",
      "data": {
        "name": "my-application",
        "version": "1.2.0",
        "type": "container"
      }
    },
    {
      "id": "source-456",
      "type": "source",
      "label": "github.com/user/repo@main",
      "data": {
        "url": "https://github.com/user/repo.git",
        "commit_hash": "abc123...",
        "branch": "main"
      }
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "from": "source-456",
      "to": "artifact-123",
      "type": "built_from",
      "label": "Built from source"
    }
  ],
  "metadata": {
    "total_nodes": 2,
    "total_edges": 1,
    "depth": 1
  },
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### Track Build Event

```http
POST /api/v1/provenance/track
Content-Type: application/json

{
  "source_ref": "git@github.com:user/repo.git@main",
  "commit_hash": "abc123...",
  "build_id": "run-123456",
  "build_system": "github-actions",
  "artifacts": [
    {
      "name": "my-application",
      "version": "1.2.0",
      "type": "container",
      "hash": "sha256:def456..."
    }
  ],
  "metadata": {
    "workflow": "build-and-deploy",
    "runner": "ubuntu-latest"
  }
}
```

### SBOM (Software Bill of Materials)

#### Generate SBOM

```http
POST /api/v1/sbom/generate
Content-Type: application/json

{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "format": "cyclonedx",
  "include_dev_dependencies": false,
  "scan_licenses": true
}
```

**Response:**

```json
{
  "id": "sbom-550e8400-e29b-41d4-a716-446655440000",
  "format": "cyclonedx",
  "version": "1.4",
  "created_at": "2024-01-15T10:30:00Z",
  "created_by": "provenance-linker",
  "components": [
    {
      "id": "comp-1",
      "name": "express",
      "version": "4.18.2",
      "type": "library",
      "namespace": "npm",
      "license": ["MIT"],
      "supplier": "TJ Holowaychuk",
      "description": "Fast, unopinionated, minimalist web framework"
    }
  ],
  "metadata": {
    "total_components": 1,
    "licenses_found": ["MIT"],
    "scan_duration": "2.3s"
  }
}
```

#### Analyze SBOM

```http
POST /api/v1/sbom/analyze
Content-Type: application/json

{
  "sbom_id": "sbom-550e8400-e29b-41d4-a716-446655440000",
  "checks": ["vulnerabilities", "licenses", "compliance"],
  "policy": {
    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
    "max_vulnerability_severity": "medium"
  }
}
```

#### Get SBOM

```http
GET /api/v1/sbom/{id}
```

#### Compare SBOMs

```http
POST /api/v1/sbom/compare
Content-Type: application/json

{
  "before_sbom_id": "sbom-old",
  "after_sbom_id": "sbom-new",
  "output_format": "json"
}
```

### Signatures and Attestations

#### Sign Artifact

```http
POST /api/v1/artifacts/{id}/sign
Content-Type: application/json

{
  "signature_type": "cosign",
  "key_id": "key-123",
  "annotations": {
    "commit": "abc123...",
    "build_id": "run-456"
  }
}
```

#### Verify Signature

```http
POST /api/v1/artifacts/{id}/verify
Content-Type: application/json

{
  "signature_id": "sig-123",
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "policy": {
    "require_rekor_entry": true,
    "allowed_issuers": ["https://accounts.google.com"]
  }
}
```

#### Create Attestation

```http
POST /api/v1/attestations
Content-Type: application/json

{
  "type": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "name": "my-application:1.2.0",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicate": {
    "buildType": "https://github.com/actions/workflow@v1",
    "builder": {
      "id": "https://github.com/actions"
    },
    "materials": [
      {
        "uri": "git@github.com:user/repo.git",
        "digest": {
          "sha1": "def456..."
        }
      }
    ]
  }
}
```

### Compliance

#### Get NIST SSDF Status

```http
GET /api/v1/compliance/nist-ssdf/status?project=my-project
```

**Response:**

```json
{
  "standard": "nist-ssdf",
  "project_name": "my-project",
  "version": "1.1",
  "status": "compliant",
  "score": 0.95,
  "requirements": [
    {
      "id": "PO.1.1",
      "title": "Identify and document software security requirements",
      "status": "compliant",
      "score": 1.0,
      "evidence": [
        "security-requirements.md",
        "threat-model.json"
      ]
    }
  ],
  "generated_at": "2024-01-15T10:30:00Z"
}
```

#### Generate Compliance Report

```http
POST /api/v1/compliance/reports
Content-Type: application/json

{
  "standard": "eu-cra",
  "project": "my-ai-system",
  "format": "pdf",
  "include_evidence": true,
  "scope": {
    "artifacts": ["artifact-123", "artifact-456"],
    "time_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-31T23:59:59Z"
    }
  }
}
```

## Error Handling

The API uses standard HTTP status codes and returns error details in JSON format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid artifact type",
    "details": {
      "field": "type",
      "allowed_values": ["container", "binary", "ml-model", "library", "document"]
    },
    "request_id": "req-550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Common Error Codes

- `400 Bad Request` - Invalid request format or parameters
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `422 Unprocessable Entity` - Validation errors
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Free tier**: 1000 requests per hour per API key
- **Pro tier**: 10000 requests per hour per API key
- **Enterprise**: Custom limits

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642248000
```

## Pagination

List endpoints support cursor-based pagination:

```http
GET /api/v1/artifacts?limit=50&cursor=eyJpZCI6IjU1MGU4NDAwIn0=
```

**Response:**

```json
{
  "data": [...],
  "pagination": {
    "has_more": true,
    "next_cursor": "eyJpZCI6IjU2MGU4NDAwIn0=",
    "total": 1500
  }
}
```

## Webhooks

Configure webhooks to receive real-time notifications:

```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "url": "https://your-app.com/webhooks/provenance",
  "events": ["artifact.created", "signature.verified", "compliance.updated"],
  "secret": "your-webhook-secret"
}
```

### Webhook Events

- `artifact.created` - New artifact registered
- `artifact.updated` - Artifact metadata changed
- `signature.created` - Artifact signed
- `signature.verified` - Signature verification completed
- `attestation.created` - New attestation added
- `compliance.updated` - Compliance status changed
- `vulnerability.detected` - New vulnerability found

## SDKs and Libraries

Official SDKs are available for popular programming languages:

### Go

```go
import "github.com/danieleschmidt/provenance-go-sdk"

client := provenance.NewClient("your-api-key")
artifact, err := client.CreateArtifact(ctx, &provenance.Artifact{
    Name:    "my-app",
    Version: "1.0.0",
    Type:    "container",
})
```

### Python

```python
from provenance_client import ProvenanceClient

client = ProvenanceClient(api_key="your-api-key")
artifact = client.create_artifact(
    name="my-app",
    version="1.0.0",
    type="container"
)
```

### Node.js

```javascript
const { ProvenanceClient } = require('@danieleschmidt/provenance-client');

const client = new ProvenanceClient({ apiKey: 'your-api-key' });
const artifact = await client.createArtifact({
  name: 'my-app',
  version: '1.0.0',
  type: 'container'
});
```

## OpenAPI Specification

The complete API specification is available in OpenAPI 3.0 format:

- [Download swagger.json](https://api.your-domain.com/swagger.json)
- [Interactive Documentation](https://api.your-domain.com/swagger-ui)

For more examples and detailed integration guides, see the [API Examples](./examples/) directory.