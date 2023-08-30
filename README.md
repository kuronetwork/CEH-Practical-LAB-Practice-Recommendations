# CEH Practical (Master) - LAB Practice Recommendations
CEH Practical &amp; Master, iLAB Practice

Based on my experience, completing all of the official iLAB modules can lead to passing the exam. I've compiled a list of iLAB exercises that can enhance your technical skills. These exercises are not just for the purpose of the exam but also to improve your penetration testing techniques.

CEH Practucal Website : 
- https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh-practical/
- https://ilabs.eccouncil.org/ethical-hacking-exercises/
- https://www.uuu.com.tw/Course/Show/1609/CEH%E5%A4%A7%E5%B8%AB%E9%9B%99%E8%AA%8D%E8%AD%89%E5%AF%A6%E6%88%B0%E8%80%83%E8%A9%A6%E7%B8%BD%E8%A4%87%E7%BF%92%E7%8F%AD

## Basic Skill

- Parrot OS and Linux command
- Basic Network concept

## Module Lab

### Module 02_Footprinting and Reconnaissance

Footprinting and reconnaissance are the initial steps in penetration testing. You need to understand the usage methods of various tools for this purpose.

2. Perform footprinting through web services
  

- Gather an email list using theHarvester
  
- Determine target OS through passive footprinting
  

4. Perform website footprinting
  

- Gather information about a target website using ping command line utility

7. Perform DNS footprinting
  

- Perform reverse DNS lookup using reverse IP domain check and DNSRecon

8. Perform network footprinting Locate the network range
  

- Perform network tracerouting in Windows and Linux Machines

9. Perform footprinting using various footprinting tools
  

- Footprinting a target using FOCA

### Module 03_Scanning Networks

Nmap is an important tool frequently utilized in penetration testing. Please learn how to use Nmap commands effectively.

1. Perform host discovery
  

- Perform host discovery using Nmap

2. Perform port and service discovery
  

- Explore various network scanning techniques using Nmap
  
- Explore various network scanning techniques using Hping3
  

3. Perform OS discovery
  

- Identify the target system’s OS with Time-to-Live (TTL) and TCP window sizes using Wireshark
  
- Perform OS discovery using Nmap Script Engine (NSE)
  

### Module 04_Enumeration

You must understand various enumeration techniques.

1. Perform NetBIOS enumeration
  

- Perform NetBIOS enumeration using Windows command-line utilities
  
- Perform NetBIOS enumeration using an NSE Script
  

2. Perform SNMP enumeration
  

- Perform SNMP enumeration using snmp-check
  
- Perform SNMP enumeration using Nmap
  

3. Perform LDAP enumeration
  

- Perform LDAP enumeration using Python and Nmap
  
- Perform LDAP enumeration using ldapsearch
  

5. Perform DNS enumeration
  

- Perform DNS enumeration using zone transfer
  
- Perform DNS enumeration using Nmap
  

7. Perform RPC, SMB, and FTP enumeration
  

- Perform RPC, SMB, and FTP enumeration using Nmap

### Module 05_Vulnerability Analysis

Vulnerability assessment tools are commonly used. Please familiarize yourself with the basic usage methods of these tools.

2. Perform vulnerability assessment using various vulnerability assessment tools
  

- Perform vulnerability analysis using OpenVAS
  
- Perform vulnerability scanning using Nessus
  

### Module 06_System Hacking

Please make sure to familiarize yourself with privilege escalation techniques.

1. Gain access to the system
  

- Perform active online attack to crack the system’s password using Responder

2. Perform privilege escalation to gain higher privileges
  

- Escalate privileges in Linux machine by exploiting misconfigured NFS
  
- Escalate privileges to gather hashdump using Mimikatz
  

3. Maintain remote access and hide malicious activities
  

- Image steganography using OpenStego and StegOnline
  
- Maintain domain persistence by exploiting Active Directory Objects
  

4. Clear logs to hide the evidence of compromise
  

- Clear Linux machine logs using the BASH shell

### Module 07_Malware Threats

Reverse engineering is challenging, but here, please focus on becoming familiar with the tools' usage.

1. Gain access to the target system using Trojans
  

- Gain control over a victim machine using the njRAT RAT Trojan

3. Perform static malware analysis
  

- Perform a strings search using BinText
  
- Identify packaging and obfuscation methods using PEid
  
- Analyze ELF executable file using Detect It Easy (DIE)
  
- Find the portable executable (PE) information of a malware executable file using PE Explorer
  
- Perform malware disassembly using IDA and OllyDbg
  
- Perform malware disassembly using Ghidra
  

4. Perform dynamic malware analysis
  

- Perform port monitoring using TCPView and CurrPorts

### Module 08_Sniffing

Please gain an understanding of network packet traffic analysis and the usage of Wireshark.

1. Perform active sniffing
  

- Perform ARP poisoning using arpspoof

2. Perform network sniffing using various sniffing tools
  

- Perform password sniffing using Wireshark

### Module 09_Social Engineering

2. Detect a phishing attack
  

- Detect phishing using Netcraft

### Module 10_Denial-of-Service

Please gain an understanding of network packet traffic analysis and the usage of Wireshark.

1. Perform DoS and DDoS attacks using various Techniques
  

- Perform a DoS attack (SYN flooding) on a target host using Metasploit
  
- Perform a DoS attack on a target host using hping3
  

### Module 11_Session Hijacking

2. Detect session hijacking
  

- Detect session hijacking using Wireshark

### Module 12_Evading IDS, Firewalls, and Honeypots

2. Evade firewalls using various evasion techniques
  

- Bypass windows firewall using Nmap evasion techniques

### Module 13_Hacking Web Servers

Web Server attack techniques are quite common. Please understand how to gather relevant version information and use cracking tools.

1. Footprint the web server
  

- Information gathering using Ghost Eye
  
- Footprint a web server using Netcat and Telnet
  
- Enumerate web server information using Nmap Scripting Engine (NSE)
  
- Uniscan web server fingerprinting in Parrot Security
  

2. Perform a web server attack
  

- Crack FTP credentials using a Dictionary Attack

### Module 14_Hacking Web Applications

Web applications often have vulnerabilities. Please understand how to gather relevant version information and utilize tools.

1. Footprint the web infrastructure
  

- Perform web application reconnaissance using Nmap and Telnet
  
- Perform web application reconnaissance using WhatWeb
  
- Perform web application vulnerability scanning using Vega
  
- Identify clickjacking vulnerability using ClickjackPoc
  

2. Perform web application attacks
  

- Perform a brute-force attack using Burp Suite
  
- Perform parameter tampering using Burp Suite
  
- Identify XSS vulnerabilities in web applications using PwnXSS
  
- Exploit parameter tampering and XSS vulnerabilities in web applications
  

### Module 15_SQL Injection

Please gain an understanding of the concept of SQL Injection and the SQLMAP tool.

1. Perform SQL injection attacks
  

- Perform an SQL injection attack on an MSSQL database
  
- Perform an SQL injection attack against MSSQL to extract databases using sqlmap
  

### Module 16_Hacking Wireless Networks

Please understand the differences between WEP, WPA, and WPA2, and become familiar with Aircrack-ng.

1. Perform wireless traffic analysis
  

- Wi-Fi packet analysis using Wireshark

2. Perform wireless attacks
  

- Crack a WEP network using Aircrack-ng
  
- Crack a WPA2 network using Aircrack-ng
  

### Module 17_Hacking Mobile Platforms

Please become knowledgeable about mobile security techniques and get familiar with adb commands and the Phonesploit tool.

1. Hack android devices
  

- Exploit the Android platform through ADB using PhoneSploit
  
- Hack an Android device by creating APK file using AndrORAT
  

2. Secure Android Devices using Various Android Security Tools
  

- Analyze a malicious app using online Android analyzers

### Module 18_IoT and OT Hacking

Please understand the packet structures of MQTT and Modbus.

1. Perform footprinting using various footprinting techniques
  

- Gather information using online footprinting tools

2. Capture and analyze IoT device traffic
  

- Capture and analyze IoT traffic using Wireshark

### Module 19_Cloud Computing

Cloud services are commonly used in our work, and I believe practicing with them is very worthwhile.

1. Perform S3 bucket enumeration using various S3 bucket enumeration tools
  

- Enumerate S3 buckets using lazys3
  
- Enumerate S3 buckets using S3Scanner
  

### Module 20_Cryptography

Cryptography is crucial in the field of information security. It's essential to understand the concept of encryption and decryption, as well as how to use cryptographic tools.

1. Encrypt the information using various cryptography tools
  

- Calculate one-way hashes using HashCalc
  
- Calculate MD5 hashes using MD5 Calculator
  
- Calculate MD5 hashes using HashMyFiles
  
- Encrypt and decrypt data using BCTextEncoder
  

4. Perform disk encryption
  

- Perform disk encryption using VeraCrypt
  
- Perform disk encryption using BitLocker Drive Encryption
  

5. Perform cryptanalysis using various cryptanalysis tools
  

- Perform cryptanalysis using CrypTool

## Engage Lab

The Engage Lab is an exercise to test your familiarity with tools and vulnerabilities. If you can solve most of the questions, you will be able to pass the exam smoothly.

- Engage 1 - 4
