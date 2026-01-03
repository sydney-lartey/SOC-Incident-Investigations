Incident Report 001
Detection and Analysis of Suspicious UDP NTP Traffic Using Zeek and Wazuh.
Investigated suspicious outbound UDP/NTP traffic using Zeek and Wazuh, identifying anomalous connection behaviour indicative of potential beaconing activity.
 
1.	Alert Summary
•	Alert ID: 100102
•	Severity: High (Level 10)
•	Detection Source: Wazuh SIEM
•	Data Source: Zeek conn.log
•	Detection Type: Anomalous outbound UDP communication
•	Date/Time (UTC): 1766566484.841842

Summary:
A high-severity alert was generated for outbound UDP traffic originating from an internal host to an external IP address over port 123 (NTP). The connection exhibited abnormal characteristics, including zero packet exchange and an unusual connection state, which may indicate beaconing behaviour or misuse of NTP for command-and-control (C2) communication.

2. Environment
•	Monitoring Platform: Wazuh SIEM
•	Network Sensor: Zeek
•	Log Type: conn.log (JSON)
•	Monitored Hosts:
o	Internal Linux server (Zeek sensor)
o	Kali Linux attack simulation host
o	Windows 11 endpoint
•	Network Type: Internal lab network with outbound internet access

Log Ingestion:
Zeek logs were ingested into Wazuh using native JSON decoding, enabling automatic field extraction without custom decoders.

3. Detection Logic
The alert was triggered by a custom Wazuh rule designed to detect outbound UDP traffic from an internal host to an external destination.
Rule Conditions:
•	proto = udp
•	local_orig = true
•	local_resp = false

Rationale:
•	UDP traffic lacks session state and is commonly abused for covert communications.
•	External UDP traffic initiated from internal hosts can indicate:
o	Beaconing behaviour
o	Misuse of common services (e.g., NTP)
o	Early-stage C2 communication

4. Investigation Steps
4.1 Log Review
The following Zeek connection record was analysed:
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

4.2 Key Indicators Observed
Indicator	Observation	Significance
Internal source	     192.168.94.138	    Host initiated connection
External destination	     185.125.190.58	    Public IP
Destination port	     123 (NTP)	    Commonly abused protocol
Packet count	     0 packets sent/received	    Abnormal
Connection state	     OTH	    Unusual for NTP
History flag	     C	    Connection attempt only

4.3 Behavioural Analysis
•	Legitimate NTP traffic typically involves bidirectional packet exchange
•	Zero packets exchanged suggests:
o	Failed communication
o	Scanning behaviour
o	Beacon attempt without payload
•	The external IP was not a known internal NTP server
 
5. Assessment
Likelihood of Malicious Activity: Medium
While NTP traffic can be legitimate, the combination of:
•	Zero packet exchange
•	Unusual connection state
•	External destination
•	No known time synchronization requirement
raises suspicion for early-stage beaconing or misconfiguration.

This activity warrants further investigation to rule out:
•	Malware C2 over UDP
•	Unauthorized time synchronization
•	Network misconfiguration

6. Recommended Actions
Immediate Actions
•	Identify the process or service on 192.168.94.138 responsible for UDP/123 traffic
•	Review host logs for scheduled tasks or suspicious binaries
•	Verify NTP configuration on the affected host
Follow-Up Actions
•	Correlate with:
o	DNS logs (dns.log)
o	Process creation logs (endpoint telemetry)
•	Monitor for repeated connections to the same destination
•	Escalate severity if frequency increases

7. Lessons Learned
•	Zeek conn.log provides high-fidelity network telemetry for behavioural detection
•	JSON-native decoding in Wazuh enables rapid rule development
•	Broad UDP detections should be refined to reduce false positives
•	Contextual analysis is essential before escalation
