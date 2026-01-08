# Detection: TCP Horizontal Port Scanning

## Related Incident
Incident 002 — Detection of TCP Port Scanning with Service Probing

## Objective
Detect reconnaissance activity characterized by a single host attempting TCP connections across many destination ports in a short time window.

## Data Sources
- Zeek `conn.log`
- Firewall connection logs
- IDS metadata (optional)

## Detection Logic (Conceptual)

Trigger on one-to-many TCP connection patterns with minimal data transfer.

Conditions:
- protocol = tcp
- short-lived connections
- multiple destination ports
- single source host

## Example Pseudocode

IF
  proto = "tcp"
  AND connection_duration < short_threshold
GROUP BY
  source_ip, destination_ip
WITHIN
  1 minute
CALCULATE
  distinct(destination_port)
TRIGGER WHEN
  distinct(destination_port) >= 20

Optional refinements:
- avg(bytes) < low_data_threshold
- connection_state IN (S0, RST, REJ)

## False Positive Considerations
- Vulnerability scanners
- Network management tools
- Authorized internal testing

Context and authorization should be verified before escalation.

## Severity
Medium

## Triage Guidance
- Identify the scanning host
- Determine whether the activity is authorized
- Correlate with endpoint telemetry for process attribution
- Monitor for follow-on exploitation attempts
