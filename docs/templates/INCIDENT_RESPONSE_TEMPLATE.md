# Incident Response Template

## Incident Information

**Incident ID:** [INC-YYYY-MMDD-XXX]  
**Date/Time Reported:** [YYYY-MM-DD HH:MM UTC]  
**Incident Commander:** [Name]  
**Severity Level:** [P0/P1/P2/P3]  
**Status:** [Investigating/Mitigating/Resolved/Closed]  

## Initial Assessment

### Incident Summary
**Brief Description:** [One-line summary of the incident]

**Detailed Description:**
```
[Comprehensive description of what happened, when it was discovered,
and how it was detected. Include any error messages, logs, or symptoms.]
```

### Impact Assessment
- **Service Availability:** [Fully Down/Partially Down/Degraded/Normal]
- **User Impact:** [All Users/Subset of Users/Internal Only/No User Impact]
- **Data Impact:** [Data Loss/Data Corruption/Data Exposure/No Data Impact]
- **Financial Impact:** [Estimated cost/revenue impact]
- **Reputation Impact:** [High/Medium/Low/None]

### Affected Systems
- [ ] **Web Application** - [Status/Impact]
- [ ] **API Services** - [Status/Impact]
- [ ] **Database Systems** - [Status/Impact]
- [ ] **Monitoring Systems** - [Status/Impact]
- [ ] **Third-party Integrations** - [Status/Impact]
- [ ] **Infrastructure** - [Status/Impact]

---

## Incident Classification

### Severity Matrix

| Level | Description | Response Time | Update Frequency |
|-------|-------------|---------------|------------------|
| P0 | Complete service outage, security breach | 15 minutes | Every 30 minutes |
| P1 | Major functionality affected, limited service | 1 hour | Every 2 hours |
| P2 | Minor functionality affected, degraded service | 4 hours | Daily |
| P3 | Minor issues, no service impact | 1 business day | Weekly |

### Incident Category
- [ ] **Availability** - Service downtime or performance issues
- [ ] **Security** - Security breach, data exposure, unauthorized access
- [ ] **Data** - Data corruption, data loss, data integrity issues
- [ ] **Performance** - Significant performance degradation
- [ ] **Integration** - Third-party service issues affecting functionality
- [ ] **Infrastructure** - Hardware, network, or cloud infrastructure issues

### Security Classification (if applicable)
- [ ] **Confidentiality Breach** - Unauthorized data disclosure
- [ ] **Integrity Compromise** - Data or system modification
- [ ] **Availability Attack** - Denial of service or system unavailability
- [ ] **Supply Chain Compromise** - Compromised dependencies or build process

---

## Timeline of Events

### Initial Discovery
**Time:** [HH:MM UTC]  
**Event:** [How the incident was discovered]  
**Reporter:** [Who reported the incident]  
**Detection Method:** [Monitoring alert, customer report, internal discovery, etc.]

### Timeline Progression
| Time (UTC) | Event | Action Taken | Person Responsible |
|------------|-------|--------------|-------------------|
| [HH:MM] | [Event description] | [Action taken] | [Name] |
| [HH:MM] | [Event description] | [Action taken] | [Name] |
| [HH:MM] | [Event description] | [Action taken] | [Name] |

---

## Response Team

### Incident Command Structure
**Incident Commander:** [Name] - [Contact info]  
**Deputy Commander:** [Name] - [Contact info]  
**Communications Lead:** [Name] - [Contact info]  

### Response Team Members
| Role | Name | Contact | Availability |
|------|------|---------|--------------|
| Technical Lead | [Name] | [Phone/Email] | [Available/On-call] |
| Security Lead | [Name] | [Phone/Email] | [Available/On-call] |
| Platform Engineer | [Name] | [Phone/Email] | [Available/On-call] |
| Database Admin | [Name] | [Phone/Email] | [Available/On-call] |
| Customer Success | [Name] | [Phone/Email] | [Available/On-call] |

### Escalation Contacts
| Level | Role | Name | Contact | When to Escalate |
|-------|------|------|---------|------------------|
| L2 | Engineering Manager | [Name] | [Contact] | P0/P1 after 2 hours |
| L3 | VP Engineering | [Name] | [Contact] | P0 after 4 hours |
| L4 | CTO | [Name] | [Contact] | P0 with customer impact |
| L5 | CEO | [Name] | [Contact] | Major security breach |

---

## Investigation and Diagnosis

### Initial Hypothesis
**Primary Hypothesis:** [Most likely cause based on initial investigation]  
**Alternative Hypotheses:** [Other possible causes to investigate]

### Investigation Steps Taken
- [ ] **System Status Checks**
  - [X] Application health endpoints
  - [X] Database connectivity
  - [ ] External service dependencies
  - [ ] Infrastructure metrics

- [ ] **Log Analysis**
  - [ ] Application logs reviewed
  - [ ] System logs analyzed
  - [ ] Security logs examined
  - [ ] Network logs investigated

- [ ] **Monitoring Data Review**
  - [ ] Performance metrics analyzed
  - [ ] Error rate trends reviewed
  - [ ] Resource utilization checked
  - [ ] Alert history examined

### Evidence Collected
1. **Log Entries:** [Location and relevant log entries]
2. **Metrics/Graphs:** [Links to monitoring dashboards]
3. **Screenshots:** [Any relevant screenshots or evidence]
4. **Error Messages:** [Specific error messages encountered]

### Root Cause Analysis
**Root Cause:** [Identified root cause of the incident]

**Contributing Factors:**
1. [Factor 1 that contributed to the incident]
2. [Factor 2 that contributed to the incident]
3. [Factor 3 that contributed to the incident]

**Why This Happened:** [Explanation of the chain of events that led to the incident]

---

## Containment and Mitigation

### Immediate Actions Taken
1. **[HH:MM UTC]** - [Immediate action to contain the incident]
2. **[HH:MM UTC]** - [Additional containment measure]
3. **[HH:MM UTC]** - [Mitigation step taken]

### Workarounds Implemented
- **Workaround 1:** [Description and implementation details]
- **Workaround 2:** [Description and implementation details]

### Systems Isolated or Disabled
- [ ] **[System/Service Name]** - [Reason for isolation]
- [ ] **[System/Service Name]** - [Reason for isolation]

### Data Protection Measures
- [ ] **Database snapshots taken** - [Timestamp and location]
- [ ] **Data backup verified** - [Backup status and integrity]
- [ ] **System state preserved** - [For forensic analysis]

---

## Resolution Steps

### Permanent Fix Implementation
**Solution:** [Description of the permanent fix]

**Implementation Steps:**
1. [Step 1 - detailed implementation]
2. [Step 2 - detailed implementation]
3. [Step 3 - detailed implementation]

### Validation and Testing
- [ ] **Fix validated in staging environment**
- [ ] **Smoke tests completed successfully**
- [ ] **Performance testing completed**
- [ ] **Security validation performed**

### Rollback Plan
**If resolution fails:**
1. [Rollback step 1]
2. [Rollback step 2]
3. [Rollback step 3]

**Rollback Triggers:**
- [Condition 1 that would trigger rollback]
- [Condition 2 that would trigger rollback]

---

## Communication Log

### Internal Communications
| Time (UTC) | Audience | Message | Method |
|------------|----------|---------|--------|
| [HH:MM] | Engineering Team | [Message content] | Slack |
| [HH:MM] | Management | [Message content] | Email |
| [HH:MM] | All Staff | [Message content] | Announcement |

### External Communications
| Time (UTC) | Audience | Message | Method |
|------------|----------|---------|--------|
| [HH:MM] | Customers | [Message content] | Status page |
| [HH:MM] | Partners | [Message content] | Email |
| [HH:MM] | Regulators | [Message content] | Official notice |

### Status Page Updates
- **[HH:MM UTC]** - Initial incident reported
- **[HH:MM UTC]** - Investigation update
- **[HH:MM UTC]** - Mitigation in progress
- **[HH:MM UTC]** - Service restored
- **[HH:MM UTC]** - Post-incident monitoring

---

## Recovery and Monitoring

### Service Recovery Checklist
- [ ] **All systems operational**
- [ ] **Performance metrics normal**
- [ ] **Error rates returned to baseline**
- [ ] **User functionality verified**
- [ ] **Data integrity confirmed**

### Post-Incident Monitoring
**Monitoring Period:** [Duration of enhanced monitoring]

**Key Metrics to Watch:**
- [Metric 1] - [Target threshold]
- [Metric 2] - [Target threshold]
- [Metric 3] - [Target threshold]

**Monitoring Schedule:**
- **First 4 hours:** Every 15 minutes
- **Next 8 hours:** Every 30 minutes
- **Next 24 hours:** Every hour
- **Following week:** Normal monitoring

### Success Criteria
- [ ] All services fully operational for 24 hours
- [ ] No related incidents reported
- [ ] Performance metrics within normal ranges
- [ ] Customer satisfaction restored

---

## Lessons Learned

### What Went Well
1. [Positive aspect of the incident response]
2. [Another thing that worked well]
3. [Effective process or tool used]

### What Could Be Improved
1. [Area for improvement in incident response]
2. [Process or tool that could be enhanced]
3. [Communication or coordination issue]

### Gaps Identified
1. **Monitoring Gap:** [Specific monitoring that could have detected this earlier]
2. **Process Gap:** [Process that was missing or inadequate]
3. **Knowledge Gap:** [Information or expertise that was lacking]
4. **Tool Gap:** [Tool or capability that would have helped]

---

## Action Items

### Immediate Actions (Within 24 hours)
- [ ] **[Action 1]** - Assigned to: [Name] - Due: [Date]
- [ ] **[Action 2]** - Assigned to: [Name] - Due: [Date]

### Short-term Actions (Within 1 week)
- [ ] **[Action 1]** - Assigned to: [Name] - Due: [Date]
- [ ] **[Action 2]** - Assigned to: [Name] - Due: [Date]

### Long-term Actions (Within 1 month)
- [ ] **[Action 1]** - Assigned to: [Name] - Due: [Date]
- [ ] **[Action 2]** - Assigned to: [Name] - Due: [Date]

### Prevention Measures
1. **Technical Improvements:**
   - [Specific technical change to prevent recurrence]
   - [Additional monitoring or alerting needed]

2. **Process Improvements:**
   - [Process change to improve response]
   - [Training or documentation update needed]

3. **Infrastructure Improvements:**
   - [Infrastructure change to improve resilience]
   - [Redundancy or failover improvement]

---

## Post-Mortem Meeting

### Meeting Details
**Date/Time:** [Scheduled post-mortem meeting]  
**Attendees:** [List of required attendees]  
**Facilitator:** [Meeting facilitator name]  

### Meeting Agenda
1. Incident timeline review
2. Root cause analysis discussion
3. Response effectiveness evaluation
4. Action items prioritization
5. Process improvement recommendations

### Key Discussion Points
- [Point 1 to discuss in detail]
- [Point 2 to discuss in detail]
- [Point 3 to discuss in detail]

---

## Metrics and Analysis

### Incident Metrics
- **Detection Time:** [Time from incident start to detection]
- **Response Time:** [Time from detection to initial response]
- **Resolution Time:** [Total time to resolve the incident]
- **Customer Impact Duration:** [Time customers were affected]

### Business Impact
- **Users Affected:** [Number/percentage of users impacted]
- **Revenue Impact:** [Estimated financial impact]
- **SLA Breach:** [Yes/No - which SLAs were affected]
- **Reputation Impact:** [Assessment of brand/reputation impact]

### Performance Against SLOs
| Service Level Objective | Target | Actual | Met? |
|------------------------|--------|--------|------|
| Service Availability | 99.9% | [Actual %] | [Yes/No] |
| Response Time | < 200ms | [Actual time] | [Yes/No] |
| Error Rate | < 0.1% | [Actual %] | [Yes/No] |

---

## Compliance and Reporting

### Regulatory Notifications
- [ ] **GDPR Breach Notification** (if applicable within 72 hours)
- [ ] **SOC 2 Incident Report** (if applicable)
- [ ] **Industry-Specific Reporting** (if required)

### Internal Reporting
- [ ] **Executive Summary** prepared and distributed
- [ ] **Board Notification** (for critical incidents)
- [ ] **Insurance Notification** (if applicable)

### Documentation Requirements
- [ ] **Incident documented in ticketing system**
- [ ] **Evidence preserved for potential legal review**
- [ ] **Customer communications archived**

---

## Sign-off and Closure

### Incident Resolution Approval
**Technical Lead:** [Name] - [Date] - [Signature]  
**Security Lead:** [Name] - [Date] - [Signature] (for security incidents)  
**Incident Commander:** [Name] - [Date] - [Signature]  

### Final Status
**Incident Status:** [Resolved/Closed]  
**Resolution Confirmed:** [Date/Time]  
**Customer Impact Ended:** [Date/Time]  
**Documentation Complete:** [Date]  

### Knowledge Base Updates
- [ ] **Runbook updated** with new procedures
- [ ] **Monitoring alerts** configured for prevention
- [ ] **Training materials** updated with lessons learned
- [ ] **FAQ updated** with customer-facing information

---

## Appendix

### Technical Details
```
[Detailed technical information, stack traces, configuration
details, or other technical data relevant to the incident]
```

### Communication Templates Used
- [Link to customer communication template]
- [Link to internal communication template]
- [Link to status page update template]

### Related Documentation
- [Link to relevant runbooks]
- [Link to system architecture diagrams]
- [Link to monitoring dashboards]
- [Link to previous similar incidents]

### Contact Information
- **24/7 Incident Hotline:** [Phone number]
- **Incident Response Team:** [Email/Slack channel]
- **Executive Escalation:** [Contact information]
- **External Support:** [Vendor support contacts]