
---
## `incident-001-suspicious-udp-ntp/timeline.md` (final text)

```md
# Timeline — Incident 001 (Suspicious UDP/NTP)

- Alert generated in Wazuh for outbound UDP traffic to external host on port 123
- Zeek `conn.log` reviewed to validate source/destination/port and connection metadata
- Identified abnormal characteristics (zero packets, conn_state=OTH, history=C)
- Assessed as suspicious with medium confidence (possible misconfiguration vs early-stage beaconing)
- Documented findings, recommended endpoint validation and correlation with DNS/host telemetry
