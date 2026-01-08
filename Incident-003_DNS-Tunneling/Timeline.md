# Timeline — Incident 003 (DNS Tunneling)

- Alert generated in Wazuh for anomalous DNS behaviour
- Zeek `dns.log` reviewed for query structure and frequency
- Identified long, high-entropy subdomains and repeated parent domain usage
- Assessed behaviour against known DNS tunneling patterns
- Validated lack of legitimate application justification
- Incident escalated for endpoint and network correlation
- Findings documented with recommended response actions
