# Intrusion-Detection
Activities on Intrusion Detection

   * **01_InvestigatingWebAppAttacks.md**
     * Focuses on web-app threats (SQLi, XSS, directory traversal).
     * Shows how to review logs, intercept traffic, and use tools like Burp Suite or Wireshark to detect web-layer intrusions.
   * **02_InvestgatingNetworkAttacks.md**
     * Covers port scans, stealth probes, brute-force attacks, protocol abuse.
     * Guides readers through packet captures and NIDS rules using tools like Snort, Suricata, and Zeek.
   * **03_NetworkVulnerabilityDiscovery.md**
     * Demonstrates network reconnaissance using scanners (Nmap, Nessus/OpenVAS).
     * Focuses on identifying vulnerable services, versioning, misconfigurations, and risk prioritization.
   * **04_InvestigatingEndpointVulnerability.md**
     * Aims at endpoint-level weaknesses.
     * Guides on checking OS settings, installed software, missing patches, insecure configurations, privilege escalation paths using EDR tools and manual auditing.
   * **05_MalwareInvestigation.md**
     * Full malware analysis workflow: detecting suspicious processes/files, static/dynamic analysis, sandbox behavior and IOC extraction.
     * Utilizes tools like strings, asset metadata, registry tracking, and reverse-engineering techniques.
   * **06_CloudSecurityMonitoring.md**
     * Designed for cloud-native environments (e.g., AWS).
     * Covers deploying IDS/IPS (Suricata, Wazuh, GuardDuty), collecting logs (CloudTrail, VPC Flow), integrity monitoring, and alert correlation for threat hunting.
   * **07_UserSecurityMonitoring.md**
     * Probably (though not yet detailed here) addresses user-based detection: monitoring user behavior, credentials, logins, abnormal sessions.
   * **08_RaccoonStealer.md**
     * Likely a case study analyzing the Raccoon Stealer malware: behavior analysis, IOC extraction, threat patterns, technical dissection.
