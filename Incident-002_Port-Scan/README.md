# Incident 002 — Network Port Scanning Activity (Zeek + Wazuh)

## Incident Summary
An alert was generated after detecting multiple outbound connection attempts from a single internal host to a range of destination ports within a short time window. This behaviour is consistent with **network reconnaissance or port scanning**, commonly observed during the early stages of an attack lifecycle.

## Alert Details
- Detection Tool: Wazuh SIEM
- Data Source: Zeek `conn.log` (JSON)
- Alert Type: Suspicious network scanning activity
- Severity: Medium–High
- Detection Method: Behavioural analysis of repeated connection attempts
- Observed Behaviour: Multiple destination ports targeted by a single source host

## Environment
- SIEM: Wazuh
- Network Monitoring: Zeek
- Log Type: `conn.log` (JSON)
- Monitored Systems:
  - Kali Linux host (attack simulation)
  - Internal Linux and Windows endpoints
- Network: Isolated home lab environment
- Ingestion: Zeek telemetry ingested into Wazuh via native JSON decoding

## Detection Logic
The detection focused on identifying **reconnaissance-style behaviour** based on connection patterns rather than payload content.

**Key indicators used:**
- Repeated connections from the same source IP
- Multiple destination ports targeted within a short timeframe
- Abnormal or failed connection states
- Minimal packet exchange per connection

**Rationale:**
Port scanning is a common reconnaissance technique used to identify open services prior to exploitation. Automated scans typically generate many short-lived or incomplete connections across a range of ports, which differs from normal application behaviour.

## Investigation Steps

### 1) Validate alert context
Reviewed Zeek `conn.log` entries associated with the alert to confirm source consistency and destination diversity.

### 2) Analyse key fields
The following fields were examined:
- `id.orig_h` (source IP)
- `id.resp_p` (destination ports)
- `conn_state`
- `orig_pkts` / `resp_pkts`
- `history`

### 3) Behavioural assessment
Observed characteristics included:
- A single host initiating connections to sequential or varied destination ports
- Low packet counts per connection
- Failed or partial connection states
- No evidence of sustained or legitimate sessions

This pattern aligns with automated scanning activity rather than normal user-driven traffic.

## Findings & Confidence
**Assessment:** Likely reconnaissance activity  
**Confidence:** Medium–High

**Considerations:**
- Behaviour strongly matched known TCP/UDP scanning techniques (e.g., Nmap-style probes)
- Benign explanations (authorised vulnerability scanning or testing) remain possible
- Source host context is required to fully validate intent

## Outcome
**Status:** Requires validation / monitored

The activity was documented as suspicious reconnaissance behaviour. Further validation is required to determine whether the scanning was authorised or malicious.

## Recommended Next Actions

### Immediate
- Identify the host responsible for the scanning activity
- Validate whether the activity was authorised (e.g., internal testing or security assessment)
- Review host processes, command history, and user activity

### Follow-up / Correlation
- Monitor for follow-on activity such as exploitation attempts or lateral movement
- Correlate with authentication logs and endpoint telemetry
- Apply rate limiting or blocking controls if scanning is unauthorised

## Lessons Learned
- Zeek provides strong visibility into early-stage reconnaissance activity
- Port scanning detection is a high-value SOC use case
- Behavioural context is essential to distinguish malicious scanning from authorised testing
- Correlation across time and hosts improves detection confidence
