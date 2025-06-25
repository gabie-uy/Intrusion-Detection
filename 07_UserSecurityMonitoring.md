# 🛡️ User Security Monitoring

## 📘 Exercise Summary

This exercise focused on detecting and analyzing user account-based attacks such as brute force, password spray, and high-confidence threat intelligence events. Using log data from various sources (Linux security logs, Okta, and Azure AD), we monitored user authentication patterns to identify and respond to signs of credential-based compromise.

---

## 🔍 Activity & Scripts

### Brute Force

```kusto
(_sourceCategory=Labs/OS/Linux/Security)
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port
```
![Brute Force Log Analysis](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/b1bcc3c3-de4f-4f63-abb6-47bf0f4bcba5)

```kusto
(_sourceCategory=Labs/OS/Linux/Security )
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port
| where status = "Failed"
```
![Failed Password Attempts](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/78beff6b-8b77-40eb-9e78-27b983e2796b)

```kusto
(_sourceCategory=Labs/OS/Linux/Security )
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port
| where status = "Failed"
| count by _timeslice, user,status,ip,port
| where _count < 50
| sort by _count
```
![Low Count Filter](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/fa505689-267a-49d4-b1f8-dbd60b8b6403)

---

### Password Spray

```kusto
(_sourceCategory=Labs/Okta)
| timeslice 15m
| where %"outcome.result" = "FAILURE"
```
![Failed Logins (Okta)](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ee0afcbd-3a57-4076-9721-b80134827204)

```kusto
(_sourceCategory=Labs/Okta )
| timeslice 15m
| where %"outcome.result" = "FAILURE"
| count_distinct(%"actor.alternateId") group by _timeslice, %"client.ipAddress"
```
![Distinct Users per IP](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/52f54ef9-6e1b-4abd-ae9e-b182a42684ba)

```kusto
(_sourceCategory=Labs/Okta)
| timeslice 15m
| where %"outcome.result" = "FAILURE"
| count_distinct(%"actor.alternateId") group by _timeslice, %"client.ipAddress"
| where _count_distinct>5
| sort by _count_distinct
```
![Filtered Spray Indicators](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1358a71d-2260-48b7-944a-dba26854513a)

---

### Threat Intelligence

```kusto
((_sourceCategory=Labs/Azure/AD))
| where operationname = "Sign-in activity"
```
![Azure Sign-in Logs](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/5ee2bf38-21bb-4b96-8dc5-f80aa38801a9)

```kusto
((_sourceCategory=Labs/Azure/AD))
| where operationname = "Sign-in activity"
| %"properties.ipAddress" as ip_address
```
![IP Extraction](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/be9b8445-85b9-4a6c-b2ea-41657c17f2a7)

```kusto
((_sourceCategory=Labs/Azure/AD))
| where operationname = "Sign-in activity"
| %"properties.ipAddress" as ip_address
| lookup type, actor, raw, threatlevel as malicious_confidence from sumo://threat/cs on threat=ip_address
| json field=raw "labels[*].name" as label_name
| replace(label_name, "\/","->") as label_name
| replace(label_name, """," ") as label_name
| where type="ip_address" and !isNull(malicious_confidence)
| if (isEmpty(actor), "Unassigned", actor) as Actor
| count by %"properties.userPrincipalName", ip_address, malicious_confidence, Actor, label_name
```
![Threat Intelligence Lookup](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1ad2d07d-ebd9-4007-8797-a016a57307d8)

---

## 🚨 Threat Detection & Analysis

### 1. Brute Force Attack

- **Summary**: Multiple failed login attempts over a short time period.
- **Indicators**: Repeated access attempts using SSH, short gaps between attempts.
- **Criticality**: 🔶 *Medium* – Not all failed attempts succeeded, but signs of credential compromise present.
- **Business Impact**:
  - *Short Term*: Compromised credentials can lead to unauthorized access.
  - *Long Term*: Loss of data integrity and potential reputational harm.

---

### 2. Password Spraying

- **Summary**: One password tested across multiple accounts to find weak/default credentials.
- **Indicators**: Single IP address targeting many accounts with login failures.
- **Criticality**: 🔴 *High* – Large-scale attempt may uncover weak passwords; high potential for escalation.
- **Business Impact**:
  - *Short Term*: User accounts may be locked or compromised.
  - *Long Term*: Attackers could elevate privileges or exfiltrate sensitive data.

---

### 3. Threat Intelligence (Ransomware Behavior)

- **Summary**: Malicious behavior flagged from known threat actor IP addresses.
- **Indicators**: Threat intelligence tags from CrowdStrike on suspicious sign-in activity.
- **Criticality**: 🔴 *High* – Ransomware behaviors observed; extremely high risk.
- **Business Impact**:
  - *Short Term*: System encryption, data exfiltration, service outages.
  - *Long Term*: Financial loss, customer distrust, potential legal liability.

---

## 🧠 SOC Analyst Actions Taken

- Investigated logs and identified brute force patterns and password spray distribution.
- Blocked suspicious IPs from further access.
- Alerted affected users and locked compromised accounts.
- Ran malware IOC queries to identify malware/ransomware behaviors tied to threat intelligence flags.
- Informed management and cybersecurity team for further response and backup restoration.

---

## 📌 What Does the Enterprise Do Next?

### 🧩 Synthesize the Investigation and Its Implications

- Correlation between brute force attempts and successful login events must be deeply audited.
- Internal users must undergo a review to validate whether logins originated from them or an adversary.
- Threat intelligence sources should be further leveraged to build proactive blocklists.

### 🛠 Remediation Plan

- Reset passwords of compromised accounts.
- Enforce MFA on all critical systems.
- Implement user behavior analytics (UBA) to baseline and detect anomalies.
- Update detection rules for brute force and password spray signatures.
- Run full antivirus/malware scans on affected assets.

### 📉 Business Implications

- **Short Term**: Temporary access denial to users; delayed operations due to investigations.
- **Long Term**: Enhanced security posture through tightened access control policies and user education.

---

## ✅ Recommendations

- Enforce strong, unique passwords and implement MFA across all systems.
- Train users to recognize login anomalies and phishing techniques.
- Schedule regular audits of access logs and user behavior.
- Integrate more advanced threat intelligence platforms to enrich future incident responses.

---

## 🔗 References

- Fortinet on [Brute Force Attacks](https://www.fortinet.com/resources/cyberglossary/brute-force-attack)  
- OWASP on [Password Spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack)  
- CrowdStrike on [Threat Intelligence](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)
