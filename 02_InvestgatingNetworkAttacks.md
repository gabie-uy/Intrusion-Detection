# 🛡️ Investigating Network Attacks

With the increasing use of public and private networks, the risk of exploitation by malicious actors has grown significantly. Attackers can infiltrate organizations and disrupt services, often leveraging foundational attacks that have evolved over time. This report discusses three key types of network attacks, analyzing their impact, methods of detection, and mitigation strategies.

## Activity

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

## Threat Simulation

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

### Post-Incident Analysis Report

#### 🔥 Incident Summary

Between [insert date range], the organization experienced multiple network anomalies and security alerts indicating malicious behavior. These included:

- **Port scanning activities** targeting various system ports.
- Evidence of the **Slammer worm** attempting denial-of-service (DoS) attacks via UDP packets.
- **Zeus Command and Control (C2) traffic** indicating botnet activity and potential credential theft.

The incidents were detected through IDS alerts, anomalous traffic volume, unauthorized access attempts, and endpoint slowdowns. Immediate containment and investigation procedures were initiated.

#### 🧾 Indicators of Compromise (IOCs)

| Type              | IOC Details                                          |
|-------------------|------------------------------------------------------|
| IP Addresses      | Unknown external IPs with abnormal port scan traffic |
| Ports             | Ports 1433 (SQL), 80, 443, 21, 23                     |
| Protocols         | TCP, UDP, HTTP                                       |
| Malware Signature | Slammer hex pattern, Zeus executable hash            |
| Behavior Patterns | Repeated pings, malformed HTTP requests, keylogging  |
| Destinations      | Outbound connections to known malicious C2 servers   |

#### ⚠️ Alert Criticality Table

| Alert Type            | Criticality | Rationale                                                                 |
|-----------------------|-------------|---------------------------------------------------------------------------|
| Port Scanning         | Medium      | May precede a targeted attack; requires prompt investigation              |
| Slammer Worm Activity | High        | Can result in DoS, disrupt services, and exploit vulnerable SQL ports     |
| Zeus C2 Communication | Critical    | Involves credential theft and botnet control; high impact and persistence |

#### ✅ Actions Taken

- Isolated affected endpoints from internal networks.
- Updated firewall rules to block malicious IPs and restrict unused ports.
- Deployed endpoint detection and response (EDR) tools across high-risk assets.
- Collected PCAPs and logs for forensic analysis.
- Patched vulnerable services (e.g., MS SQL Server).
- Quarantined suspicious files and disabled suspicious user accounts.
- Sent alert to all users about potential phishing attempts.

#### 🧠 Root Cause Analysis

| Incident Component      | Root Cause                                                               |
|-------------------------|--------------------------------------------------------------------------|
| Port Scanning           | Lack of strict external access controls and exposed unused ports.        |
| Slammer Worm Attempt    | Unpatched SQL Server instances vulnerable to buffer overflow exploits.   |
| Zeus Botnet Activity    | User clicked phishing email attachment, leading to malware installation. |

#### 📘 Lessons Learned

- **User awareness is critical** — The Zeus infection originated from human error (email click).
- **Legacy systems remain a risk** — Slammer exploited outdated SQL infrastructure.
- **Proactive monitoring** — Earlier detection would have prevented malware persistence.
- **IOCs must be correlated** — Multi-stage attacks require cross-system visibility and context.

#### ✅ Recommendations

- Implement **network segmentation** to isolate critical assets.
- Enforce **least privilege access** and remove default or unused service accounts.
- Conduct **regular patch management cycles**, particularly on legacy systems.
- Roll out **mandatory security awareness training** for all employees.
- Enable **advanced threat detection tools** (e.g., EDR, anomaly-based NIDS).
- Establish a **threat-hunting program** to proactively detect stealthy threats.

---

## Business Implications

The investigation uncovered a coordinated pattern of probing, malware propagation, and C2 communication—indicating a likely prelude to a larger campaign. The combination of Slammer and Zeus suggests a hybrid threat model: one designed to destabilize (worm) and one to extract sensitive data (botnet).

> **Implication**: Without aggressive remediation, the organization risks system compromise, customer data loss, financial theft, and reputational damage.

### Business Impact (Long-term & Short-term)

#### 📉 Short-Term Business Implications
- **Operational Downtime:** Systems may need to be taken offline for patching and forensic analysis.
- **Resource Disruption:** IT teams are pulled away from other tasks to focus on incident response.
- **Customer Trust Impact:** Clients may become temporarily concerned if disruptions are public-facing.
- **Increased Cost:** Emergency response may require third-party consultants or overtime resources.

#### 📈 Long-Term Business Implications
- **Brand and Reputation Damage:** Persistent security issues erode customer trust and industry credibility.
- **Regulatory Exposure:** Potential compliance violations (e.g., GDPR, HIPAA) may result in audits or fines.
- **Financial Impact:** Loss of business, legal liabilities, and the cost of upgrading infrastructure.
- **Increased Insurance Premiums:** Cyber insurance rates may rise due to breach history.
- **Strategic Realignment:** Security maturity will become a top board-level priority, influencing IT roadmaps.


## Enterprise Actions

| Remediation Step                         | Status      | Outcome                                                              |
|------------------------------------------|-------------|----------------------------------------------------------------------|
| System patching                          | ✅ Completed | Vulnerabilities closed on SQL and exposed services                   |
| User credential reset                    | ✅ Completed | Reset compromised and high-risk user credentials                     |
| Network hardening                        | ✅ Completed | Firewall, port filtering, segmentation rules enforced                |
| Security tools deployment                | ✅ Completed | EDR deployed to high-value systems                                   |
| User awareness campaign                  | 🔄 Ongoing  | Company-wide phishing awareness training scheduled                   |
| IOC blocklisting across infrastructure   | ✅ Completed | Prevented future C2 and worm activity                                |

---

## 📚 References

- [How to protect yourself from the Zeus virus – NordVPN](https://nordvpn.com/blog/zeus-virus/)
- [Zeus Virus – Kaspersky](https://usa.kaspersky.com/resource-center/threats/zeus-virus)
- [Malware of the Day - Zeus – Active Countermeasures](https://www.activecountermeasures.com/malware-of-the-day-zeus/)
- [Security for Microsoft Windows System Administrators – Rountree, D. (2011)](https://doi.org/10.1016/b978-1-59749-594-3.00012-0)
- [What is a computer worm? – Norton](https://us.norton.com/blog/malware/what-is-a-computer-worm#)
- [What is a port scan? – Fortinet](https://www.fortinet.com/resources/cyberglossary/what-is-port-scan)
- [What is Port Scanning? – Datto Networking](https://www.datto.com/blog/what-is-port-scanning)
