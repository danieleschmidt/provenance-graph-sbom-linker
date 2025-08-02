# ADR-0003: Cryptographic Verification Strategy

## Status
Accepted

## Context
The provenance system must provide cryptographic guarantees about artifact authenticity and integrity. We need to support multiple signature formats, key management approaches, and verification policies to accommodate diverse enterprise environments.

## Decision
We will implement a multi-layered cryptographic verification system that supports multiple signature schemes and provides policy-based verification workflows.

### Supported Signature Schemes
1. **Sigstore/Cosign**: Keyless signing with transparency log verification
2. **Traditional GPG**: For organizations with existing GPG infrastructure
3. **PKI Certificates**: Enterprise CA-issued code signing certificates
4. **Hardware Security Modules (HSM)**: For high-security environments

### Verification Policies
- **Mandatory Verification**: All production artifacts must have valid signatures
- **Multi-Signature**: Critical artifacts require multiple independent signatures
- **Threshold Policies**: Configurable quorum requirements (e.g., 2 of 3 signatures)
- **Time-bound Verification**: Signatures must be recent and not expired

### Trust Store Management
- **Centralized Trust Store**: Redis-backed key and certificate storage
- **Policy-driven Trust**: Dynamic trust decisions based on organizational policies
- **Revocation Support**: Real-time checking of certificate/key revocation status
- **Trust Delegation**: Hierarchical trust relationships for large organizations

## Consequences

### Positive
- **Security**: Strong cryptographic guarantees about artifact authenticity
- **Flexibility**: Support for diverse organizational security requirements
- **Compliance**: Meets regulatory requirements for software supply chain security
- **Auditability**: Complete verification history for forensic analysis
- **Scalability**: Distributed verification across multiple trust anchors

### Negative
- **Complexity**: Multiple signature schemes increase implementation complexity
- **Performance**: Verification operations can be CPU-intensive
- **Key Management**: Secure key distribution and rotation is challenging
- **Dependencies**: Reliance on external services (Sigstore, HSMs)

### Mitigation Strategies
- Implement signature verification caching to improve performance
- Use hardware acceleration for cryptographic operations where available
- Provide comprehensive key management documentation and tooling
- Implement graceful degradation when external services are unavailable

## Implementation Details

### Signature Verification Flow
1. **Artifact Ingestion**: Extract embedded signatures and metadata
2. **Policy Lookup**: Determine applicable verification policies
3. **Trust Chain Validation**: Verify signatures against trust store
4. **Transparency Log Check**: Validate against public transparency logs
5. **Result Storage**: Store verification results in provenance graph

### Key Rotation Strategy
- **Automated Rotation**: Support for automated key rotation workflows
- **Grace Periods**: Configurable overlap periods during key transitions
- **Emergency Revocation**: Immediate revocation capabilities for compromised keys
- **Audit Trails**: Complete history of key lifecycle events

## Security Considerations
- Store private keys in HSMs or secure key management services
- Implement rate limiting to prevent signature verification DoS attacks
- Use secure communication channels for all key exchange operations
- Regular security audits of cryptographic implementations

## Related ADRs
- ADR-0001: Use Neo4j for Provenance Graph
- ADR-0002: Event-Driven Architecture for Provenance Tracking