# 🛡️ Investigating Network Attacks

## 📌 Abstract

With the increasing use of public and private networks, the risk of exploitation by malicious actors has grown significantly. Attackers can infiltrate organizations and disrupt services, often leveraging foundational attacks that have evolved over time. This report discusses three key types of network attacks, analyzing their impact, methods of detection, and mitigation strategies.

### Network Attacks Covered

1. **Port Scanning**
2. **Worms – Slammer**
3. **Command and Control – Zeus**

> _The report examines how enterprises can respond to these threats, assess their severity, evaluate their impact on operations, and develop remediation strategies._

---

## 🔍 Three Network Attacks

### 1. Port Scanning

Port scanning is a reconnaissance technique used to identify open, closed, or filtered ports in a system. It serves as an entry point for potential exploitation.

**Key Characteristics:**
- Identifies active ports, OS, and services.
- Detects open/closed/filtered ports.
- Can indicate presence of firewalls or weak authentication.

**Indicators of Compromise:**
- Device slowdown.
- Unexpected data transfers.
- High volume of packets to specific ports.

**Criticality & Business Impact:**
- Varies based on targeted ports and frequency.
- Can lead to performance degradation and system downtime.
- May result in reputational and financial damage.

**Recommended Mitigations:**
- Use firewalls and TCP wrappers.
- Regularly audit and update security systems.
- Monitor for suspicious traffic patterns.

---

### 2. Slammer Worm

The Slammer Worm is a fast-spreading worm that exploited vulnerabilities in Microsoft SQL Server, leading to denial-of-service (DoS) conditions.

**Attack Behavior:**
- Rapid propagation through IP address space.
- Sends excessive payloads to crash servers.

**Detection:**
- High volume of ping requests from unknown sources.
- Spike in traffic to SQL ports.

**Criticality & Business Impact:**
- Immediate disruption of services.
- Potential for major operational downtime.
- Loss of customer trust and financial resources.

**Recommended Mitigations:**
- Keep systems and software up to date.
- Implement anti-virus/anti-malware solutions.
- Educate users on safe email and network practices.

---

### 3. Zeus Command and Control

Zeus is a malware toolkit used to create botnets aimed at stealing banking information and sensitive credentials.

**Attack Behavior:**
- Installs silently via phishing or malicious links.
- Steals credentials, keystrokes, HTTP data.
- Forms a botnet for remote command execution.

**Detection:**
- Sluggish system performance.
- Unknown applications or processes.
- Unauthorized banking activity.

**Criticality & Business Impact:**
- High—directly compromises financial data.
- Long-term: data breaches, customer trust erosion.
- Legal and regulatory consequences.

**Recommended Mitigations:**
- Use VPNs, ad-blockers, and anti-malware tools.
- Educate employees about phishing and fake websites.
- Monitor network traffic for command-and-control patterns.

---

## 📸 Figures

### 🔎 Port Scanning

**Figure 1.1** – Threat Analysis  
![Port Scanning 1](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f362e47e-4ce0-4976-b892-3c0b1ef86520)

**Figure 1.2** – Threat Analysis  
![Port Scanning 2](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/d4cf99aa-cb4e-4e69-b059-c3c3e546aa8d)

**Figure 1.3** – Summary  
![Port Scanning Summary](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/5a66c611-02d4-474e-a04a-ea366ac36016)

### 🧬 Slammer Worm

**Figure 2.1** – Hex Dump  
![Slammer Hex](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/77913cbc-8f6b-4250-b276-15a01615e8ed)

**Figure 2.2** – Endpoints  
![Slammer Endpoints](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/2535d5fe-c1c4-425c-8484-058e3d544c48)

**Figure 2.3** – Threat Analysis  
![Slammer Analysis](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/68cbc358-4d8b-47ba-a3bd-967736cdec50)

### 🕵️ Zeus Command & Control

**Figure 3.1** – Destination Port Packets  
![Zeus Packets](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/850101ff-df30-4937-b73d-08ae87cd9b05)

**Figure 3.2** – Packet Length  
![Zeus Length](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e4c6d09b-2f9a-4996-ac0f-2d3175f32b55)

**Figure 3.3** – HTTP Requests  
![Zeus HTTP 1](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e3a95999-2bca-4025-9646-49c73aefe0f3)

**Figure 3.4** – HTTP Request  
![Zeus HTTP 2](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/7478d416-6d64-4cfd-99f6-40df43094391)

---

## 📚 References

- [How to protect yourself from the Zeus virus – NordVPN](https://nordvpn.com/blog/zeus-virus/)
- [Zeus Virus – Kaspersky](https://usa.kaspersky.com/resource-center/threats/zeus-virus)
- [Malware of the Day - Zeus – Active Countermeasures](https://www.activecountermeasures.com/malware-of-the-day-zeus/)
- [Security for Microsoft Windows System Administrators – Rountree, D. (2011)](https://doi.org/10.1016/b978-1-59749-594-3.00012-0)
- [What is a computer worm? – Norton](https://us.norton.com/blog/malware/what-is-a-computer-worm#)
- [What is a port scan? – Fortinet](https://www.fortinet.com/resources/cyberglossary/what-is-port-scan)
- [What is Port Scanning? – Datto Networking](https://www.datto.com/blog/what-is-port-scanning)
