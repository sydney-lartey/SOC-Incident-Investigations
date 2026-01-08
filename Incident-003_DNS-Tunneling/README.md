# 1. Overview

This incident documents the investigation of anomalous DNS activity indicative of DNS tunneling. The activity was characterized by high-frequency DNS queries containing long, high-entropy subdomains originating from a single internal host.

Through packet capture and Zeek analysis, the traffic was validated as unicast DNS over UDP/53 and explicitly ruled out multicast name resolution (mDNS/LLMNR). The behavior was ultimately classified as DNS tunneling consistent with covert command-and-control or data exfiltration.

This sets the tone: clear, confident, not sensational.

# 2. Detection

The investigation began after observing abnormal DNS query patterns during network traffic analysis. These patterns included unusually long subdomain labels, non-human-readable character distributions, and sustained query frequency from a single internal host.

Initial hypotheses included:

Legitimate but noisy name resolution

Multicast DNS or LLMNR traffic

DNS tunneling or covert channel activity

This shows analytical discipline — not jumping to conclusions.

# 3. Evidence Collection

Network traffic was captured on a dedicated Zeek sensor using tcpdump, with filtering applied to UDP port 53 to focus on DNS activity. The resulting packet capture was parsed using Zeek with checksum validation disabled to account for virtualized network offloading.

The following Zeek logs were generated and analyzed:

conn.log — connection-level metadata

dns.log — DNS query and response details

This is where you reference the setup without dumping commands.

# 4. Analysis & Validation
### 4.1 Transport Validation: DNS vs mDNS/LLMNR

Connection-level analysis confirmed that all suspicious traffic occurred over unicast DNS (UDP/53) to the internal resolver at 192.168.94.2. No traffic was observed on UDP/5353 or UDP/5355, ruling out mDNS and LLMNR as potential causes.

Screenshot reference:

Figure 1: conn.log showing unicast UDP/53 traffic and absence of multicast DNS ports.

This is one of your strongest differentiators.

## 4.2 Query Structure and Entropy

Analysis of dns.log revealed DNS queries with near-maximum-length subdomain labels and high-entropy character sets consistent with encoded payloads. Many queries followed a sequential pattern, further indicating automated generation rather than human-driven domain lookups.

Screenshot reference:

Figure 2: Long, high-entropy DNS queries extracted from dns.log.

This is the flagship visual.

## 4.3 Source Attribution and Frequency

Query frequency analysis showed that a single internal host (192.168.94.136) was responsible for the majority of anomalous DNS traffic. Other hosts generated minimal DNS activity, suggesting the behavior was isolated rather than network-wide.

Screenshot reference:

Figure 3: DNS query volume by source host.

This clearly scopes the incident.

# 5. Conclusion and Classification

Based on transport validation, query structure, entropy, and frequency analysis, the activity was classified as DNS tunneling. The behavior is consistent with covert command-and-control communication or data exfiltration over DNS.

The incident was scoped to a single internal host, with no evidence of lateral propagation during the observation window.

Clear, decisive, but still evidence-driven.

# 6. Recommended Response Actions

Isolate the affected host (192.168.94.136) from the network

Block or sinkhole suspicious domain patterns at the DNS resolver

Perform host-based forensic analysis to identify the originating process and persistence mechanisms

Implement behavioral DNS monitoring, including query length, entropy, and per-host rate baselining
