# Incident 001 — Validation of Outbound UDP / NTP Traffic
### Overview

This incident documents the detection and investigation of outbound UDP traffic over port 123 (Network Time Protocol). The objective was to determine whether the observed activity represented malicious behavior or legitimate time synchronization, and to establish a baseline for normal UDP/NTP behavior within the environment.

The investigation confirmed the traffic as legitimate NTP communication, serving as a baseline reference for subsequent incidents involving anomalous UDP behavior.

## 1. Alert Summary

- Alert ID: 100102

- Severity: Low / Informational

- Detection Source: Wazuh SIEM

- Data Sources: Zeek conn.log, ntp.log

- Detection Type: Outbound UDP traffic over port 123

- Timestamp (UTC): 1766566484.841842

### Summary

- Outbound UDP traffic from an internal host to an external destination on port 123 triggered an alert for review. Due to the use of UDP and an external NTP server, the activity required validation to determine whether it was legitimate time synchronization or anomalous behavior.

## 2. Environment

- Monitoring Platform: Wazuh SIEM

- Network Sensor: Zeek (Ubuntu)

- Packet Capture: tcpdump

- Log Types Analyzed:

  - conn.log

  - ntp.log

Hosts Involved:

- Windows 11 endpoint (NTP client)

- Linux systems

- Network Type: Internal lab network with outbound internet access

### Log Ingestion

Zeek logs were ingested into Wazuh using native JSON decoding, enabling structured field extraction without custom decoders.

## 3. Detection Logic

The alert was generated based on outbound UDP traffic observed from an internal host to an external destination.

Rule Conditions

- proto = udp

- id.resp_p = 123

- local_orig = true

### Rationale

- UDP traffic is stateless and commonly monitored for abuse.

- Outbound NTP traffic should be validated to distinguish legitimate time synchronization from misuse, misconfiguration, or anomalous behavior.

This detection is designed for visibility and validation, not automatic escalation.

## 4. Investigation and Analysis
### 4.1 Connection-Level Evidence

The following connection metadata was extracted from Zeek conn.log:

{

  "id.orig_h": "192.168.94.138",

  "id.resp_h": "185.125.190.56",
  
  "id.resp_p": 123,
  
  "proto": "udp",
  
  "service": "ntp",
  
  "orig_bytes": 48,
  
  "resp_bytes": 48

}

### 4.2 Key Indicators
Indicator	                Observation	                Interpretation

Source IP	                192.168.94.138	            Internal endpoint

Destination IP	          185.125.190.56	            External NTP server

Destination Port	        123	                        Standard NTP

Protocol	                UDP	                        Expected for NTP

Payload Size	            48 / 48 bytes	              Symmetric, expected

Service                   NTP	                        Identified by Zeek

### 4.3 Protocol-Level Validation

Analysis of Zeek ntp.log confirmed the traffic as legitimate Network Time Protocol activity:

- Bidirectional request/response exchange

- Expected payload sizes

- Short connection duration

- No excessive polling or repeated beaconing patterns

This behavior aligns with normal NTP synchronization.

## 5.0 Assessment

#### Likelihood of Malicious Activity: Low

The activity was classified as legitimate outbound NTP traffic based on:

- Successful bidirectional communication

- Expected payload symmetry

- Positive protocol identification by Zeek

- Absence of anomalous frequency or volume

No indicators of command-and-control, tunneling, or misuse of UDP/123 were observed.

## 6.0 Recommended Actions
### Immediate Actions

- No containment required

- Document activity as baseline NTP behavior

### Monitoring Recommendations

- Maintain visibility into outbound UDP/123 traffic

- Establish per-host NTP baselines

- Alert only on deviations such as:

  - Excessive query frequency

  - Payload size anomalies

  - Communication with untrusted destinations

## 7.0 Lessons Learned

- UDP-based alerts require protocol-level validation before escalation

- Zeek’s protocol analyzers provide critical context beyond connection metadata

- Establishing baselines is essential for accurate anomaly detection

- Proper validation prevents false positives and alert fatigue

### Why This Incident Matters

This investigation demonstrates disciplined SOC analysis by validating potentially suspicious activity before escalation. Establishing a baseline for legitimate NTP traffic enables higher-confidence detection of anomalous UDP behavior in later investigations.
