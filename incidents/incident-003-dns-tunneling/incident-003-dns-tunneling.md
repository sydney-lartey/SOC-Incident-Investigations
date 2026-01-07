Detection and Analysis of Potential DNS Tunnelling Activity.
 
1. Alert Summary
  •	Alert Type: Suspicious DNS behaviour
  •	Severity: Medium–High
  •	Detection Source: Wazuh SIEM
  •	Data Source: Zeek dns.log
  •	Detection Method: Behavioural analysis of DNS query patterns
Summary:
Suspicious DNS activity was detected involving repeated DNS queries with unusually long and irregular subdomain names. The behaviour deviated from normal DNS resolution patterns and was indicative of potential DNS tunnelling or covert command-and-control (C2) communication.

2. Environment
  •	SIEM Platform: Wazuh
  •	Network Monitoring: Zeek
  •	Log Type: dns.log (JSON format)
  •	Monitored Hosts:
  o	Internal Linux and Windows endpoints
  o	Kali Linux host used for attack simulation
  •	Network Type: Home lab with controlled outbound DNS access
Zeek DNS logs were ingested into Wazuh using native JSON decoding, enabling analysis of query names, frequency, and response behaviour.

3. Detection Logic

The detection focused on identifying abnormal DNS query characteristics commonly associated with tunnelling.
Indicators Used:
  •	Excessively long domain names
  •	High entropy or random-looking subdomains
  •	Repeated queries to the same domain
  •	High query frequency over a short period
  •	Lack of corresponding legitimate application behaviour
Rationale:
  •	DNS tunnelling encodes data within subdomains
  •	Encoded data appears random and significantly longer than typical hostnames
  •	Malware often uses DNS to bypass firewall restrictions

4. Investigation Steps

4.1 Log Review
Zeek dns.log entries were reviewed for query structure and frequency.
Key fields analysed:
  •	query
  •	qtype_name
  •	rcode_name
  •	id.orig_h
  •	answers
  •	trans_id

4.2 Key Indicators Observed
Indicator                	Observation	                     Significance
Unusually long queries    Encoded-looking subdomains	     Possible data exfiltration
High frequency     	      Multiple queries per minute	     Beaconing or tunnelling
Repeated domain	          Same parent domain	             C2 endpoint
Low DNS response value 	  Minimal answers	                 Signalling channel

4.3 Behavioural Analysis
  •	Legitimate DNS queries are typically short and human-readable
  •	The observed subdomains appeared algorithmically generated
  •	Query frequency exceeded what is expected for standard applications
  •	No known internal service justified the DNS activity

5. Assessment

Likelihood of Malicious Activity: Medium to High
The observed DNS behaviour closely aligned with known DNS tunnelling techniques used for:
  •	Command-and-control communication
  •	Data exfiltration
  •	Evasion of network controls
While legitimate edge cases exist (e.g., CDNs, telemetry), the pattern warranted escalation and deeper inspection.

6. Recommended Actions
Immediate Actions:
  •	Identify the endpoint generating the DNS queries
  •	Inspect running processes and scheduled tasks on the host
  •	Block or sinkhole the suspicious domain if confirmed malicious
Follow-Up Actions:
  •	Correlate DNS activity with:
    o	Network connections (conn.log)
    o	Endpoint process logs
  •	Monitor for data volume increases or persistence
  •	Escalate to incident response if additional indicators appear

7. Lessons Learned
  •	DNS is a common and effective C2 channel
  •	Behavioural analysis is critical for detecting DNS tunnelling
  •	High-frequency, high-entropy queries are strong indicators
  •	Correlation across logs improves confidence and reduces false positives
  
