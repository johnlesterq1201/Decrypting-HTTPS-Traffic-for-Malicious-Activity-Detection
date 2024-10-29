# Decrypting-HTTPS-Traffic-for-Malicious-Activity-Detection

# Objective
The goal of this analysis is to identify and document any malicious activities or processes observed within network traffic using Wireshark.

### Skills Learned

- Identifying Malicious Patterns in Encrypted Traffic
- Experience with Network Forensics
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity

# Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

Ref 1: Network Diagram

# Summary of Findings
During the analysis of network traffic on the PCAP File, suspicious patterns were identified, including a suspicious file being downloaded on unsafe website.

#Summary of Key Findings:

Finding Type	Description	Risk Level
Suspicious IP Address	[List specific IP addresses identified]	High
Malicious Payload	[Details on detected payload]	Medium
Anomalous Activity	[Brief description]	High
3. Detailed Analysis
3.1 Malicious IP Address Detection
IP Address: [Example: 192.168.1.10]
Protocol: [e.g., TCP, UDP]
Port: [Example: Port 80]
Details: Traffic analysis showed that this IP address was associated with high data transfers outside business hours, potentially exfiltrating sensitive information.
Screenshot/Evidence:
(Attach a screenshot from Wireshark with key evidence highlighted)

# Malicious Payload Analysis
Payload Details: [e.g., Contains shellcode, suspicious GET requests]
Traffic Type: [HTTP, HTTPS, etc.]
Details: Analysis of payload contents showed a clear attempt at [describe, e.g., data exfiltration, buffer overflow attack]. The request parameters suggest [specific attack vector].
Screenshot/Evidence:
# Recommended Actions
Immediate Blocking: Block the IP addresses identified as malicious on the firewall.
Update Signatures: Ensure intrusion detection/prevention signatures are up-to-date to catch similar activity.
Review Logs: Perform a detailed review of the endpoint and network logs related to the affected machines for potential compromise.
# Conclusion
This analysis highlights the importance of continuous monitoring and proactive measures to identify and contain potential threats. Implementing the recommended actions will help mitigate the risks identified.
