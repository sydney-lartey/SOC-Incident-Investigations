# Detection: Abnormal NTP (UDP/123) Activity

## Related Incident
Incident 001 — Validation of Outbound UDP / NTP Traffic

## Objective
Detect anomalous use of UDP port 123 that deviates from established NTP baseline behavior, without alerting on normal time synchronization.

## Data Sources
- Zeek `conn.log`
- Zeek `ntp.log`
- Network firewall logs (optional)

## Detection Logic (Conceptual)

Trigger when outbound UDP/123 traffic exhibits abnormal characteristics.

Conditions:
- protocol = udp
- destination_port = 123
- local_orig = true

Behavioral thresholds:
- connection_count per host > baseline
- asymmetric byte counts (orig_bytes ≠ resp_bytes)
- sustained or high-frequency polling
- communication with untrusted or uncommon NTP servers

## Example Pseudocode

IF
  proto = "udp"
  AND dest_port = 123
GROUP BY
  source_ip
WITHIN
  10 minutes
CALCULATE
  count(connections),
  avg(orig_bytes),
  avg(resp_bytes)
TRIGGER WHEN
  count(connections) > baseline_threshold
  OR byte_asymmetry_detected = true

## False Positive Considerations
- Legitimate NTP traffic is:
  - Low frequency
  - Symmetric in payload size
  - Periodic
- Alerts should be informational unless behavior deviates from baseline.

## Severity
Low / Informational

## Triage Guidance
- Validate protocol-level NTP activity using `ntp.log`
- Confirm destination is a trusted NTP server
- Escalate only if behavior is sustained or anomalous
