# Security Review Template

## Review Information

**Reviewer:** [Security reviewer name]  
**Date:** [Review date]  
**PR/Branch:** [Link to pull request or branch]  
**Risk Level:** [Low/Medium/High/Critical]  

## Change Summary

**Description:** [Brief description of the changes being reviewed]

**Components Affected:**
- [ ] Authentication/Authorization
- [ ] Data Processing
- [ ] API Endpoints
- [ ] Database Operations
- [ ] External Integrations
- [ ] Infrastructure/Configuration
- [ ] Cryptographic Operations
- [ ] Supply Chain Components

---

## Security Review Checklist

### Authentication & Authorization
- [ ] **Authentication mechanisms are properly implemented**
  - Multi-factor authentication support where required
  - Secure password handling (hashing, salting)
  - Session management follows best practices
  - Token validation and expiration handling

- [ ] **Authorization controls are comprehensive**
  - Role-based access control (RBAC) implementation
  - Principle of least privilege enforced
  - Resource-level access controls
  - Permission escalation prevented

- [ ] **Identity management is secure**
  - User enumeration attacks prevented
  - Account lockout mechanisms in place
  - Secure password reset functionality
  - Audit logging for authentication events

**Notes:**
```
[Additional notes on authentication/authorization review]
```

### Input Validation & Data Protection
- [ ] **All inputs are properly validated**
  - Server-side validation for all user inputs
  - Input sanitization prevents injection attacks
  - File upload restrictions and validation
  - Size limits and rate limiting implemented

- [ ] **Data protection measures are adequate**
  - Sensitive data encrypted at rest
  - Data in transit protected with TLS
  - PII handling follows privacy policies
  - Data retention and deletion policies enforced

- [ ] **Injection vulnerabilities prevented**
  - SQL injection protection (parameterized queries)
  - Command injection prevention
  - NoSQL injection protection
  - LDAP injection prevention

**Notes:**
```
[Additional notes on input validation and data protection]
```

### API Security
- [ ] **API endpoints are properly secured**
  - Authentication required for protected endpoints
  - Authorization checks for each operation
  - Rate limiting implemented
  - API versioning handled securely

- [ ] **Request/Response handling is secure**
  - Request size limits enforced
  - Response doesn't leak sensitive information
  - Error messages don't reveal system details
  - CORS policies properly configured

- [ ] **API documentation security**
  - Swagger/OpenAPI specs don't expose sensitive data
  - Example requests don't contain real credentials
  - Security requirements clearly documented
  - Rate limiting and throttling documented

**Notes:**
```
[Additional notes on API security]
```

### Cryptographic Operations
- [ ] **Cryptographic implementation is secure**
  - Industry-standard algorithms used (AES, RSA, etc.)
  - Proper key generation and management
  - Secure random number generation
  - Key rotation mechanisms in place

- [ ] **Digital signatures and verification**
  - Signature algorithms are current and secure
  - Signature verification properly implemented
  - Certificate chain validation
  - Revocation checking implemented

- [ ] **Key management practices**
  - Keys stored securely (HSM, key vault)
  - Key access logging and monitoring
  - Key backup and recovery procedures
  - Separation of duties for key operations

**Notes:**
```
[Additional notes on cryptographic operations]
```

### Supply Chain Security
- [ ] **Dependency management is secure**
  - All dependencies scanned for vulnerabilities
  - Dependency versions pinned
  - License compatibility verified
  - No known malicious packages included

- [ ] **SBOM generation and management**
  - SBOM accurately reflects all components
  - SBOM includes transitive dependencies
  - SBOM format compliance (SPDX, CycloneDX)
  - SBOM integrity protection (signatures)

- [ ] **Provenance tracking implementation**
  - Build provenance recorded accurately
  - Source code provenance maintained
  - Deployment provenance tracked
  - Provenance integrity verified

**Notes:**
```
[Additional notes on supply chain security]
```

### Infrastructure & Configuration
- [ ] **Container security measures**
  - Base images from trusted sources
  - Images scanned for vulnerabilities
  - Runtime security policies enforced
  - Secrets not embedded in images

- [ ] **Network security configuration**
  - Network segmentation properly implemented
  - Firewall rules follow least privilege
  - TLS configuration is secure
  - Service mesh security enabled

- [ ] **Secrets management**
  - No hardcoded secrets in code
  - Secrets stored in secure vault
  - Secrets rotation implemented
  - Access to secrets properly logged

**Notes:**
```
[Additional notes on infrastructure security]
```

### Logging & Monitoring
- [ ] **Security events are properly logged**
  - Authentication attempts logged
  - Authorization failures recorded
  - Sensitive data access tracked
  - Administrative actions audited

- [ ] **Monitoring and alerting configured**
  - Security alerts defined and tested
  - Anomaly detection implemented
  - Incident response procedures documented
  - Log retention policies enforced

- [ ] **Privacy considerations addressed**
  - PII not logged in plaintext
  - Log access properly controlled
  - Log anonymization where required
  - GDPR/privacy compliance maintained

**Notes:**
```
[Additional notes on logging and monitoring]
```

---

## Vulnerability Assessment

### Identified Issues

#### High Severity Issues
1. **Issue:** [Description of high severity issue]
   - **Impact:** [Potential security impact]
   - **Recommendation:** [Specific remediation steps]
   - **Timeline:** [Required fix timeline]

#### Medium Severity Issues
1. **Issue:** [Description of medium severity issue]
   - **Impact:** [Potential security impact]
   - **Recommendation:** [Specific remediation steps]
   - **Timeline:** [Required fix timeline]

#### Low Severity Issues
1. **Issue:** [Description of low severity issue]
   - **Impact:** [Potential security impact]
   - **Recommendation:** [Specific remediation steps]
   - **Timeline:** [Required fix timeline]

### Security Recommendations

#### Immediate Actions Required
- [ ] [Action 1 - Critical security fix]
- [ ] [Action 2 - High priority security improvement]

#### Short-term Improvements (Within 30 days)
- [ ] [Improvement 1]
- [ ] [Improvement 2]

#### Long-term Enhancements (Future releases)
- [ ] [Enhancement 1]
- [ ] [Enhancement 2]

---

## Testing Requirements

### Security Testing Checklist
- [ ] **Static Application Security Testing (SAST)**
  - Gosec scan completed and reviewed
  - Semgrep rules executed
  - Custom security rules applied
  - No high/critical issues remaining

- [ ] **Dynamic Application Security Testing (DAST)**
  - OWASP ZAP scan performed
  - Penetration testing completed (if required)
  - API security testing conducted
  - Runtime security verification

- [ ] **Software Composition Analysis (SCA)**
  - Dependency vulnerability scan
  - License compliance verification
  - Malware scanning of dependencies
  - Supply chain risk assessment

- [ ] **Container Security Testing**
  - Container image vulnerability scan
  - Runtime security policy testing
  - Network policy validation
  - Secrets scanning in containers

### Test Results Summary
```
SAST Results: [Pass/Fail] - [Number] issues found
DAST Results: [Pass/Fail] - [Number] issues found
SCA Results: [Pass/Fail] - [Number] vulnerabilities
Container Scan: [Pass/Fail] - [Number] issues found
```

---

## Compliance Assessment

### Regulatory Compliance
- [ ] **GDPR Compliance** (if applicable)
  - Data processing lawful basis established
  - Data subject rights implemented
  - Privacy by design principles followed
  - Data breach notification procedures

- [ ] **SOC 2 Compliance** (if applicable)
  - Security controls implemented
  - Availability requirements met
  - Processing integrity maintained
  - Confidentiality measures in place

- [ ] **Industry-Specific Requirements**
  - [Specify relevant industry standards]
  - [Compliance requirements met]

### Internal Policy Compliance
- [ ] **Security Policy Compliance**
  - Code signing requirements met
  - Secure development guidelines followed
  - Third-party integration policies adhered to
  - Data classification policies enforced

- [ ] **Supply Chain Policy Compliance**
  - Approved vendor list compliance
  - Open source license policies followed
  - Supply chain security standards met
  - Risk assessment completed

---

## Risk Assessment

### Risk Rating Matrix

| Risk Factor | Rating | Justification |
|-------------|--------|---------------|
| Data Sensitivity | [Low/Medium/High] | [Explanation] |
| Attack Surface | [Low/Medium/High] | [Explanation] |
| User Impact | [Low/Medium/High] | [Explanation] |
| Business Impact | [Low/Medium/High] | [Explanation] |

### Overall Risk Assessment
**Risk Level:** [Low/Medium/High/Critical]  
**Risk Score:** [Numerical score if using quantitative assessment]

**Risk Justification:**
```
[Detailed explanation of the overall risk assessment, including factors
that contribute to the risk level and any mitigating circumstances]
```

### Risk Mitigation Strategies
1. **[Risk Item 1]**
   - Mitigation: [Specific mitigation approach]
   - Owner: [Responsible team/person]
   - Timeline: [Implementation timeline]

2. **[Risk Item 2]**
   - Mitigation: [Specific mitigation approach]
   - Owner: [Responsible team/person]
   - Timeline: [Implementation timeline]

---

## Review Decision

### Final Recommendation
- [ ] **Approve** - No security issues identified, ready for merge
- [ ] **Approve with Conditions** - Minor issues that can be addressed post-merge
- [ ] **Request Changes** - Security issues must be addressed before merge
- [ ] **Reject** - Critical security issues require complete rework

### Conditions for Approval (if applicable)
1. [Condition 1 - specific requirement]
2. [Condition 2 - follow-up action needed]

### Follow-up Requirements
- [ ] Security testing verification
- [ ] Documentation updates
- [ ] Training requirements
- [ ] Monitoring setup

---

## Reviewer Sign-off

**Security Reviewer:** [Name]  
**Date:** [Date]  
**Signature:** [Digital signature or approval method]  

**Additional Reviewers:**
- **CISO/Security Lead:** [Name] - [Date] (for high-risk changes)
- **Architecture Review:** [Name] - [Date] (for infrastructure changes)

---

## Post-Review Actions

### Immediate Actions
- [ ] Communicate findings to development team
- [ ] Update security tracking system
- [ ] Schedule follow-up review if needed

### Monitoring and Validation
- [ ] Set up security monitoring for changes
- [ ] Schedule post-deployment security validation
- [ ] Update security documentation

### Knowledge Sharing
- [ ] Share learnings with security team
- [ ] Update security review guidelines
- [ ] Conduct security awareness session if needed

---

## Appendix

### Security Tools Used
- **SAST Tools:** [List of tools and versions]
- **DAST Tools:** [List of tools and versions]
- **SCA Tools:** [List of tools and versions]
- **Manual Review Tools:** [List of tools used]

### Reference Materials
- [Security policy documents]
- [Compliance requirements]
- [Industry standards referenced]
- [Security best practices guides]

### Contact Information
- **Security Team:** security-team@company.com
- **Security Lead:** [Name and contact]
- **Emergency Contact:** [24/7 security hotline]