# Alerting Runbooks for Provenance Graph SBOM Linker

## Overview

This document provides step-by-step procedures for responding to alerts from the Provenance Graph SBOM Linker monitoring system. Each runbook includes diagnosis steps, resolution procedures, and escalation paths.

## General Response Guidelines

### Alert Severity Levels

- **Critical**: Immediate response required (within 15 minutes)
- **Warning**: Response required within 1 hour
- **Info**: Response required within 4 hours during business hours

### Initial Response Process

1. Acknowledge the alert
2. Check the system status dashboard
3. Review recent changes and deployments
4. Follow the specific runbook for the alert
5. Document actions taken
6. Update stakeholders on resolution

---

## Supply Chain Security Alerts

### UnsignedArtifactInProduction

**Alert**: An unsigned artifact has been detected in production

**Impact**: High - Security compliance violation

**Diagnosis Steps**:
1. Check the alert details for artifact name and timestamp
2. Verify the artifact signature status:
   ```bash
   kubectl exec -it deployment/provenance-linker -- \
     ./provenance-linker verify --artifact {{ $labels.artifact_name }}
   ```
3. Check deployment logs:
   ```bash
   kubectl logs -l app=provenance-linker --since=1h | grep {{ $labels.artifact_name }}
   ```

**Resolution**:
1. **Immediate**: Block the unsigned artifact from production
   ```bash
   kubectl patch deployment {{ $labels.deployment }} -p '{"spec":{"replicas":0}}'
   ```
2. **Short-term**: Re-sign the artifact or rollback to signed version
3. **Long-term**: Review deployment pipeline to prevent unsigned artifacts

**Escalation**: Security team immediately, Platform team within 30 minutes

---

### SignatureVerificationFailure

**Alert**: High signature verification failure rate detected

**Impact**: High - Potential security compromise

**Diagnosis Steps**:
1. Check verification failure logs:
   ```bash
   kubectl logs -l component=signature-verifier --since=10m | grep "verification failed"
   ```
2. Analyze failure patterns:
   ```bash
   promql: rate(provenance_verifications_total{result="failure"}[5m]) by (artifact_type, failure_reason)
   ```
3. Check key management system status

**Resolution**:
1. If key rotation issue: Update verification keys
2. If artifact corruption: Re-fetch and verify artifacts
3. If systematic issue: Enable signature verification bypass (emergency only)

**Escalation**: Security team immediately

---

### HighSeverityVulnerabilityDetected

**Alert**: Critical vulnerability detected in SBOM

**Impact**: High - Security risk in production

**Diagnosis Steps**:
1. Identify the vulnerable component:
   ```bash
   promql: provenance_sbom_vulnerabilities{severity="critical"}
   ```
2. Check CVE details and CVSS score
3. Determine affected services and deployments

**Resolution**:
1. **Immediate**: Assess impact and create incident ticket
2. **Short-term**: Apply patches or implement workarounds
3. **Long-term**: Update dependency management policies

**Escalation**: Security team within 15 minutes, Product team within 1 hour

---

## System Performance Alerts

### HighAPILatency

**Alert**: 95th percentile API latency above threshold

**Impact**: Medium - User experience degradation

**Diagnosis Steps**:
1. Check current latency distribution:
   ```bash
   promql: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, endpoint))
   ```
2. Identify slow endpoints:
   ```bash
   kubectl logs -l app=provenance-linker --since=5m | grep "slow_query"
   ```
3. Check database performance:
   ```bash
   kubectl exec -it neo4j-0 -- cypher-shell "CALL dbms.listQueries() YIELD query, elapsedTimeMillis WHERE elapsedTimeMillis > 1000"
   ```

**Resolution**:
1. Scale up application replicas if needed
2. Optimize slow database queries
3. Enable request throttling if overloaded

**Escalation**: Platform team within 30 minutes

---

### SBOMProcessingBacklog

**Alert**: SBOM processing queue size above threshold

**Impact**: Medium - Processing delays

**Diagnosis Steps**:
1. Check queue metrics:
   ```bash
   promql: sbom_processing_queue_size
   ```
2. Check processor health:
   ```bash
   kubectl get pods -l component=sbom-processor
   ```
3. Review processing logs for errors:
   ```bash
   kubectl logs -l component=sbom-processor --since=10m | grep ERROR
   ```

**Resolution**:
1. Scale up SBOM processor replicas
2. Clear stuck jobs from the queue
3. Increase resource limits if needed

**Escalation**: Platform team within 1 hour

---

### GraphDatabaseConnectionFailure

**Alert**: Cannot connect to Neo4j database

**Impact**: Critical - Core functionality unavailable

**Diagnosis Steps**:
1. Check Neo4j pod status:
   ```bash
   kubectl get pods -l app=neo4j
   ```
2. Check Neo4j logs:
   ```bash
   kubectl logs neo4j-0 --tail=100
   ```
3. Test connectivity:
   ```bash
   kubectl exec -it deployment/provenance-linker -- nc -zv neo4j 7687
   ```

**Resolution**:
1. Restart Neo4j pods if unhealthy
2. Check storage and memory resources
3. Restore from backup if data corruption

**Escalation**: Platform team immediately, Database team within 15 minutes

---

## Infrastructure Alerts

### HighMemoryUsage

**Alert**: Memory usage above 85% threshold

**Impact**: Medium - Potential performance issues

**Diagnosis Steps**:
1. Identify memory usage by container:
   ```bash
   kubectl top pods --sort-by=memory
   ```
2. Check for memory leaks:
   ```bash
   kubectl logs -l app=provenance-linker | grep "OutOfMemory\|memory leak"
   ```

**Resolution**:
1. Increase memory limits for affected pods
2. Restart pods showing memory leaks
3. Scale out if sustained high usage

**Escalation**: Platform team within 1 hour

---

### DiskSpaceLow

**Alert**: Disk space below 10% on instance

**Impact**: High - Risk of service failure

**Diagnosis Steps**:
1. Check disk usage:
   ```bash
   kubectl exec -it <pod> -- df -h
   ```
2. Identify large files:
   ```bash
   kubectl exec -it <pod> -- du -sh /* | sort -hr
   ```

**Resolution**:
1. Clean up old logs and temporary files
2. Increase persistent volume size
3. Archive or delete unnecessary data

**Escalation**: Platform team immediately

---

## Security Incident Alerts

### MaliciousPackageDetected

**Alert**: Malicious package detected in project

**Impact**: Critical - Security breach potential

**Diagnosis Steps**:
1. Identify the malicious package:
   ```bash
   promql: malicious_packages_detected_total
   ```
2. Check affected projects and deployments
3. Review package scan reports

**Resolution**:
1. **Immediate**: Quarantine affected deployments
2. **Short-term**: Remove malicious packages and redeploy
3. **Long-term**: Review package approval process

**Escalation**: Security team immediately, All hands if widespread

---

### UnauthorizedProvenanceModification

**Alert**: Unauthorized attempt to modify provenance data

**Impact**: Critical - Data integrity compromise

**Diagnosis Steps**:
1. Check audit logs:
   ```bash
   kubectl logs -l component=provenance-api | grep "unauthorized_modification"
   ```
2. Identify the source of modification attempt
3. Verify current provenance data integrity

**Resolution**:
1. **Immediate**: Block the source IP/user
2. **Short-term**: Restore provenance data from backup
3. **Long-term**: Review access controls and authentication

**Escalation**: Security team immediately, Incident response team

---

## Escalation Procedures

### Internal Escalation

1. **Level 1**: On-call engineer
2. **Level 2**: Platform team lead
3. **Level 3**: Engineering manager
4. **Level 4**: CTO/VP Engineering

### External Communication

- **Customer impact**: Customer success team within 1 hour
- **Security incidents**: Legal/compliance team within 2 hours
- **Data breaches**: Executive team and legal immediately

### Communication Channels

- **Slack**: #incidents (critical), #alerts (warnings)
- **PagerDuty**: Critical alerts only
- **Email**: incident-response@company.com
- **Phone**: Emergency escalation tree

---

## Post-Incident Actions

1. **Immediate**: Document timeline and actions taken
2. **Within 24 hours**: Conduct post-mortem meeting
3. **Within 1 week**: Complete incident report and action items
4. **Within 1 month**: Implement preventive measures

### Post-Mortem Template

- **Incident Summary**: What happened and when
- **Impact Assessment**: Services affected and duration
- **Root Cause Analysis**: Why it happened
- **Timeline**: Detailed sequence of events
- **Response Analysis**: What went well and what didn't
- **Action Items**: Preventive measures and improvements

---

## Contact Information

- **Platform Team**: platform-team@company.com
- **Security Team**: security-team@company.com
- **On-Call Engineer**: +1-555-ONCALL
- **Emergency Hotline**: +1-555-EMERGENCY

## Additional Resources

- [Monitoring Dashboard](https://grafana.company.com/d/provenance-overview)
- [Alert Manager](https://alertmanager.company.com)
- [Incident Response Plan](https://wiki.company.com/incident-response)
- [Security Playbooks](https://wiki.company.com/security-playbooks)