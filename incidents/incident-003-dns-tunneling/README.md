# Incident 003 — Potential DNS Tunneling Activity (Zeek + Wazuh)

## Incident Summary
Suspicious DNS activity was detected involving repeated queries with unusually long, irregular subdomain names. The behaviour deviated from normal DNS resolution patterns and is consistent with techniques commonly used for **DNS tunneling or covert command-and-control (C2)** communication.

## Alert Details
- Detection Tool: Wazuh SIEM
- Data Source: Zeek `dns.log` (JSON)
- Alert Type: Suspicious DNS behaviour
- Severity: Medium–High
- Detection Method: Behavioural analysis of DNS query structure and frequency

## Environment
- SIEM: Wazuh
- Network Monitoring: Zeek
- Log Type: `dns.log` (JSON)
- Monitored Systems:
  - Internal Linux and Windows endpoints
  - Kali Linux host (attack simulation)
- Network: Home lab with controlled outbound DNS access
- Ingestion: Zeek DNS telemetry ingested into Wazuh using native JSON decoding

## Detection Logic
The detection focused on identifying **DNS query characteristics** commonly associated with tunneling activity.

**Indicators evaluated:**
- Excessively long domain names
- High-entropy or random-looking subdomains
- Repeated queries to the same parent domain
- High query frequency over a short time window
- Lack of corresponding legitimate application behaviour

**Rationale:**
DNS tunneling encodes data into subdomains, which results in long, random-looking queries. Malware frequently abuses DNS as it is typically allowed through network controls and inspected less deeply than other protocols.

## Investigation Steps

### 1) Validate DNS query patterns
Reviewed Zeek `dns.log` entries associated with the alert, focusing on query structure and repetition.

**Key fields analysed:**
- `query`
- `qtype_name`
- `rcode_name`
- `id.orig_h`
- `answers`
- `trans_id`

### 2) Behavioural analysis
The following characteristics were observed:
- Repeated queries to the same parent domain
- Subdomains significantly longer than typical hostnames
- Subdomains appearing algorithmically generated
- Query frequency exceeding expected application behaviour
- Minimal or low-value DNS responses

### 3) Contextual validation
- No known internal service or application justified the observed DNS activity
- Query structure and frequency were inconsistent with CDNs or legitimate telemetry services
- Behaviour aligned with known DNS-based C2 and tunneling techniques
- During investigation, DNS-related UDP traffic to multicast addresses (224.0.0.251/252) on port 5353 was observed. This was identified as mDNS service discovery traffic rather than recursive DNS resolution. While it initially appeared anomalous due to lack of responses and S0 connection states, destination addressing and port usage confirmed benign behaviour.

## Findings & Confidence
**Assessment:** Likely malicious DNS tunneling behaviour  
**Confidence:** Medium–High

**Why not “High”?**
- Certain legitimate edge cases exist (e.g., CDNs, analytics, telemetry)
- Endpoint confirmation is required to fully validate intent

**Why escalation is justified:**
- High-entropy, long subdomains
- Consistent query repetition
- Behavioural alignment with known tunneling techniques

## Outcome
**Status:** Escalated for deeper investigation

The incident was escalated due to the likelihood of DNS being used as a covert communication channel. Additional endpoint and network correlation is required to confirm compromise and scope.

## Recommended Next Actions

### Immediate
- Identify the endpoint generating the DNS queries
- Inspect running processes, scheduled tasks, and persistence mechanisms
- Validate whether the domain is known or authorised

### Follow-up / Correlation
- Correlate DNS activity with:
  - Zeek `conn.log` for outbound connections
  - Endpoint process creation and network telemetry
- Monitor for increases in data volume or sustained beaconing
- Block or sinkhole the domain if confirmed malicious

## Lessons Learned
- DNS is a common and effective channel for covert C2 communication
- Behavioural analysis is critical for detecting DNS tunneling
- High-frequency, high-entropy queries are strong indicators
- Correlation across DNS, network, and endpoint logs improves confidence and reduces false positives
