# Incident 001 — Suspicious Outbound UDP/NTP Traffic (Zeek + Wazuh)

## Incident Summary
A high-severity alert was generated for outbound UDP traffic from an internal host to an external IP on port **123 (NTP)**. The connection showed **zero packets exchanged** and an abnormal Zeek connection state, which can indicate **blocked or failed communication**, **misconfiguration**, or early-stage **beaconing/C2** behaviour.

## Alert Details
- Detection Tool: Wazuh SIEM
- Data Source: Zeek `conn.log` (JSON)
- Alert / Rule ID: 100102
- Severity: High (Level 10)
- Detection Type: Anomalous outbound UDP communication
- Observed Timestamp (UTC): 1766566484.841842

## Environment
- SIEM: Wazuh
- Network Sensor: Zeek
- Monitored Systems: Linux (Zeek sensor), Windows 11 endpoint, Kali Linux (attack simulation)
- Network: Isolated lab network with outbound internet access
- Ingestion: Zeek JSON logs ingested into Wazuh using native JSON decoding (field extraction without custom decoders)

## Detection Logic
The alert was triggered by a custom detection rule designed to flag **outbound UDP traffic** initiated by an internal host to an external destination:

**Rule conditions (high level):**
- `proto = udp`
- `local_orig = true`
- `local_resp = false`

**Rationale:**
UDP is connectionless and can be abused for covert communication. Outbound UDP to external destinations may indicate:
- Beaconing/C2 attempts
- Misuse of common services (e.g., NTP)
- Misconfiguration or unauthorised time synchronisation

## Investigation Steps

### 1) Validate the alert in network telemetry
Reviewed the associated Zeek `conn.log` entry:

```json
{
  "id.orig_h": "192.168.94.138",
  "id.resp_h": "185.125.190.58",
  "id.resp_p": 123,
  "proto": "udp",
  "conn_state": "OTH",
  "orig_pkts": 0,
  "resp_pkts": 0,
  "history": "C"
}
