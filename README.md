# Decrypting-HTTPS-Traffic-for-Malicious-Activity-Detection

# Objective
The goal of this analysis is to identify and document any malicious activities or processes observed within network traffic using Wireshark.

### Skills Learned

- Identifying Malicious Patterns in Encrypted Traffic
- Experience with Network Forensics
- Utilization of Open Source Intelligence tools (Virustotal)
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity

# Steps

1) To begin analyzing the PCAP file, let's first load it up. Once it's loaded, we can navigate to the protocol hierarchy. This will give us a clear view of the distribution of network traffic protocols within the capture. It’s a great way to understand the different types of traffic we're dealing with.

![image](https://github.com/user-attachments/assets/4cee1982-a7d2-40ac-9940-a3fece675578)

2) Based on the information gathered, we can see that we have different procotol in the PCAP file but one thing that stands out is the TLS which is the encrypted protocol.

![image](https://github.com/user-attachments/assets/16688b2b-9d0b-40a7-9202-d4a70008d0ff)

3) In this case we will use the filter = "tls.handshake.type eq 1" this filter can seperate tls traffic with the message "Client Hello" which is the initial connection for tls handshake as seen below in the screenshot.

![image](https://github.com/user-attachments/assets/22e21202-9758-4b9c-bc5e-b83809a09db1)

4) If we try to use the "TCP stream" it will help visualize the transmission happened in the packet. However, as per the screenshot, it is a scrambled word and letters since it is encrypted. 

![image](https://github.com/user-attachments/assets/e7a7ac28-c151-4b3e-92aa-27d28f99f0a7)

5) To decrypt this packet, we need to use keys based on the encryption being used. Once decrypted. we can now see the inside of the packet. Also, we found out that there's a file that was downloaded due to "GET" which is a https request method

![image](https://github.com/user-attachments/assets/a1ce2814-2742-4fc9-a3ce-c131da8451c4)

6) Using the information from "GET" request we can filter the wireshark to help us what files was downloaded. We can use the filter "http.request.method" == "GET". Upon inspection, we can see that there was a suspicious file name "invest_20.dll". By looking further, we can see the suspicious load inside the file, as shown in the screenshot 2

![image](https://github.com/user-attachments/assets/824bcbd5-58d0-466e-8bd7-c4d54c94e12c)

![image](https://github.com/user-attachments/assets/7f2b2507-d54d-4721-889f-45474c470e7a)

7) One main features of the wireshark is that we're able reassemble to packet to download the file on your local computer.

![image](https://github.com/user-attachments/assets/d2f17617-9867-4604-b712-d8858216ea3c)


8) Once we have downloaded the file in our local Computer. We can use the Linux Terminal the get the Hash of the file to futher investigate with the use of Open Source Intelligence such as VirusTotal

![image](https://github.com/user-attachments/assets/23b5146f-4d70-449a-843a-6b08efe80055)

9) Now we will copy the MD5 has value of the file and use the virustotal for further validation. Based on Virustotal, we can now found a malicious file in the network.

Note: The malicious activity will depends on the network being investigated, there are maybe one or more malicious payloads hidden in the network.

![image](https://github.com/user-attachments/assets/3929ac4d-dfc8-4509-ad2d-88d1d61dfdbf)



# Summary of Findings
During the analysis of network traffic on the PCAP File, suspicious patterns were identified, including a suspicious file being downloaded on unsafe website.

#Summary of Key Findings:

Detailed Analysis
- Malicious IP Address Detection
  
- IP Address: 10.4.1.101

- Protocol: HTTP

- Port: 80

- Details: Traffic analysis showed that this IP address was associated with a request which downloads a malicious file

# Malicious Payload Analysis
- Payload Details: Suspicious Get Request

- Traffic Type: HTTP

- Details: Analysis of the payload contents showed a clear attempt at a malicious activity. The request parameters suggest a potential attack vector, specifically indicating that the link is designed to download a file named "invest20.dll." As investigated, it could lead to unauthorized execution of code on the target system. Further investigation into the source of this request and any related network traffic is essential to fully assess the threat and implement appropriate mitigation measures.

# Recommended Actions
- Immediate Blocking: Block the IP addresses identified as malicious on the firewall.
  
- Update Signatures: Ensure intrusion detection/prevention signatures are up-to-date to catch similar activity.

- Review Logs: Perform a detailed review of the endpoint and network logs related to the affected machines for potential compromise.

