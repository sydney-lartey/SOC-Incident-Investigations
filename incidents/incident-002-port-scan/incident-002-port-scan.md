Detection and Analysis of Port Scanning Activity.

1. Alert Summary
  •	Alert Type: Suspicious network scanning activity
  •	Severity: Medium–High
  •	Detection Source: Wazuh SIEM
  •	Data Source: Zeek conn.log
  •	Detection Method: Behavioural analysis of repeated connection attempts
  •	Observed Behaviour: Multiple connection attempts to different destination ports from a single source host
Summary:
An alert was generated after observing multiple outbound connection attempts from a single internal host to multiple destination ports within a short time window. This behaviour is consistent with network reconnaissance or port scanning activity.

2. Environment
  •	SIEM Platform: Wazuh
  •	Network Monitoring: Zeek
  •	Log Type: conn.log (JSON format)
  •	Monitored Hosts:
    o	Kali Linux host (attack simulation)
    o	Internal Linux and Windows endpoints
  •	Network Type: Isolated home lab environment
Zeek network telemetry was ingested into Wazuh using native JSON decoding, allowing direct field-based rule matching.

3. Detection Logic
The detection focused on identifying multiple connection attempts originating from a single host to multiple destination ports.
Indicators Used:
  •	Repeated connections from the same source IP
  •	Multiple destination ports within a short timeframe
  •	Abnormal connection states or failed connections
Rationale:
  •	Port scanning is commonly used during reconnaissance to identify open services
  •	Repeated failed or incomplete connections are a strong indicator of scanning behaviour
  •	Early detection allows defenders to identify potential threats before exploitation
   
4. Investigation Steps
   
4.1 Log Review
Zeek conn.log entries showed multiple connections sharing the same source IP but targeting different destination ports.
Key fields reviewed:
  •	id.orig_h (source IP)
  •	id.resp_p (destination port)
  •	conn_state
  •	orig_pkts / resp_pkts
  •	history

4.2 Key Indicators Observed
Indicator                	        Observation                          Significance
Repeated source IP	    Single host initiating connections	    Indicates reconnaissance
Multiple ports	            Sequential destination ports	      Typical scan pattern
Low packet counts	          Minimal traffic per connection	      Scan probing
Connection states	            Failed or partial connections    	No legitimate session established

4.3 Behavioural Analysis
  •	Legitimate applications typically communicate with specific ports, not a wide range
  •	The observed pattern suggested automated probing rather than user activity
  •	The behaviour matched known TCP/UDP scanning techniques used by tools such as Nmap

6. Assessment
   
Likelihood of Malicious Activity: Medium to High
The activity strongly resembled reconnaissance behaviour. While benign causes (e.g., vulnerability scanning tools) are possible, such activity should be validated and monitored closely, especially if originating from an unexpected host.

8. Recommended Actions
   
Immediate Actions
  •	Identify the host responsible for the scanning activity
  •	Validate whether the activity was authorized (e.g., internal testing)
  •	Review host processes and command history
Follow-Up Actions
  •	Monitor for escalation attempts (exploitation, lateral movement)
  •	Correlate with authentication logs and endpoint telemetry
  •	Block or rate-limit suspicious scanning behaviour if unauthorized

10. Lessons Learned
  •	Zeek provides strong visibility into early-stage reconnaissance
  •	Port scanning detection is a high-value SOC use case
  •	Behavioural context is essential to distinguish malicious scans from authorized testing
  •	Correlation across time significantly improves confidence
