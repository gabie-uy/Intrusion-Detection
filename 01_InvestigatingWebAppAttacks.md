# Investigating Web Application Attacks

---

#### Table of Contents
> 1. Activity
> 2. Threat Simulation
> 3. Response
>   - Post-Incident Report
>   - What Does the Enterprise Do Next?

---

A structured approach to examining web app attacks—identifying vulnerabilities, following attack trails, and deploying tools to uncover, analyze, and attribute malicious behavior.

### Attributes

- **Timestamp** - Date reference of the transaction
- **Client IP** - This is the Internet Protocol (IP) address of the client making the request on the web service
- **Method** - Defines a set of request methods to indicate the desired action to be performed for a given resource
  
    | Method  | Description           |
    |---------|-----------------------|
    | `POST`  | Create                |
    | `GET`   | Read                  |
    | `PUT`   | Update / Replace      |
    | `PATCH` | Update / Modify       |
    | `DELETE`| Remove resource       |

- **Resource** - A resource is the thing living on the other side of a URI and a URI only points to one resource. An example is a page, file, or image.
- **Status Code** - Status codes are issued by a server in response to a client's request made to the server

    | Code Range | Meaning         |
    |------------|-----------------|
    | `1xx`      | Informational    |
    | `2xx`      | Success          |
    | `3xx`      | Redirection      |
    | `4xx`      | Client Error     |
    | `5xx`      | Server Error     |

- **User-Agent String** - A characteristic string that lets servers and network peers identify the application, browser, operating system, vendor, and/or version of the requesting user agent.

---

## Activity

### 1. Filter

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/3582db80-6e0a-4460-adb9-4ece0ac0468f)


_Initial log filter targeting Apache access logs from the Labs environment._

    sourceCategory=Labs/Apache/Access

- Filters logs to include only those tagged under Labs/Apache/Access, isolating Apache access logs from the Labs environment.

 ### 2. Geolocation & ASN Lookup
 
 ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a058174a-f75e-4050-8db9-8bb58410eb7d)

_Enhances Apache logs by mapping IPs to geographic and organizational data._

     _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip

- Retrieves geo-location data (e.g., country, city) and ASN (Autonomous System Number) information for each src_ip in the logs.

### 3. Count and Sort by IP Details

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a6457449-6229-466d-87f0-a9462f9a33cc)

_Aggregates and ranks requests by source IP and user agent for threat identification._

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | count by src_ip, country_name, organization, user_agent
    | sort by _count

- Counts log entries grouped by IP, country, organization, and browser agent.
- Sorts the results to identify the most frequent sources.

### 4. Shellshock Exploit Detection

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/853f2fa0-09da-43ee-8ea3-9ba403d9f501)

_Detects Shellshock-style attacks based on suspicious user agent patterns._

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | where user_agent matches "*() { :; }*"
    | count by src_ip, country_name, organization, user_agent
    | sort by _count

- Filters user agents matching Shellshock exploit signature.
- Shows top offending IPs using that pattern. 

### 5. 404 Error Analysis

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/c53cdfb3-c7ba-4e65-8cbd-e4b9af2556b2)

_Identifies frequent 404 errors that may indicate reconnaissance or misconfigurations._

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by src_ip, country_name, organization, user_agent, status_code
    | sort by _count

- Focuses on failed requests (404) to detect scanning or broken link activity. 

### 6. Time-based 404 Activity

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1cebe28d-ede1-43ef-9d9a-2bcb15de70dc)

_Tracks hourly 404 error trends to detect scanning bursts._

    _sourceCategory=Labs/Apache/Access 
    | timeslice 60m 
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by _timeslice, src_ip, country_name, organization, user_agent, status_code 
    | sort by _count 

- Slices time into hourly buckets to monitor when 404s spike.

### 7. Alert on Excessive 404s

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a3aa4b1b-0c66-4f14-a7a0-c907e19b6cb8)

_Alerts on unusually high 404 activity to surface potential threats._

    _sourceCategory=Labs/Apache/Access
    | timeslice 60m
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by _timeslice, src_ip, country_name, organization, user_agent, status_code
    | where _count > 20
    | sort by _count 
 
- Flags any IP with more than 20 404 errors in an hour—likely suspicious.

### 8. Excessive Success (200) Detection

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f54006d5-0336-4f88-8387-66e5912be0ca)

_Detects high-volume successful access, possibly indicating abuse or scraping._

    _sourceCategory=Labs/Apache/Access 
    | timeslice 1m 
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "200"
    | count by _timeslice, src_ip, country_name, organization, status_code 
    | where _count > 50 
    | sort by _count 

- Monitors for a high number of successful hits (status 200) per minute.
- Indicates scraping, brute force, or DoS-like behaviors.

### 9. Threat Intelligence Lookup

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/769498db-8214-4015-ab76-f2b4cd57bb2b)

_Matches IPs against threat intelligence to detect known malicious actors._    

    _sourceCategory=Labs/Apache/Access
    | lookup type, actor, raw, threatlevel from sumo://threat/cs on threat=src_ip

- Enriches log data by checking if the src_ip is linked to known threats.

### 10. Filter Confirmed Threats

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/8a4d37c4-a156-4c9a-8776-9973c014c7f6)

    _sourceCategory=Labs/Apache/Access
    | lookup type, actor, raw, threatlevel from sumo://threat/cs on threat=src_ip 
    | where !(isNull(threatlevel))

- Shows only IPs confirmed to have a threat level assigned.


## Threat Simulation 

### Post-Incident Analysis Report

#### Incident Summary

A security analysis was conducted on Apache web server access logs, which revealed multiple indicators of suspicious or malicious behavior. These included:

- Attempts to exploit the Shellshock vulnerability.
- High volumes of HTTP 404 Not Found errors (indicative of reconnaissance).
- Bursts of successful 200 OK responses from singular IPs (suggesting automation or scraping).
- Inbound traffic from known malicious IPs found in threat intelligence databases.

These alerts indicated that the web application was being targeted by automated scanners, known threat actors, and possibly bots attempting to discover or exploit vulnerabilities.

#### Indicators of Compromise (IOCs)

| IOC Type               | Example                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------- |
| **User-Agent Payload** | `() { :; };` — indicates Shellshock attack signature                                   |
| **HTTP Status Codes**  | High `404` errors (path discovery), high `200` response rate (scraping or brute force) |
| **IP Addresses**       | Matched with threat intelligence feeds (`threatlevel` present)                         |
| **User-Agent Strings** | Repeated non-human user-agents (bots or scripts)                                       |

#### Actions Taken

| Alert Type               | Response Action                                                                    |
| ------------------------ | ---------------------------------------------------------------------------------- |
| **Shellshock Detection** | Logged payloads, blocked malicious IPs, validated Bash patch status                |
| **404 Recon Activity**   | Rate-limited offenders, monitored common path hits, updated WAF rules              |
| **200 OK Spike**         | Identified access patterns, applied CAPTCHA/rate limits, blacklisted abusive IPs   |
| **Threat Intel Matches** | Blocked IPs at firewall, searched logs for related events, notified internal teams |

#### Root Cause Analysis

- Initial Entry Point: Public-facing Apache web server receiving direct HTTP requests.
- Weaknesses:
    - Lack of real-time alerting for known exploit patterns.
    - Incomplete throttling for high-frequency requests.
    - Limited integration with live threat intelligence feeds.
- Exposure: Attackers were able to conduct scanning and low-level exploit attempts without immediate interruption until post-log analysis.

#### Lessons Learned
- Signature-based detection is still highly effective—Shellshock was clearly identifiable via user-agent analysis.
- High 404 errors often precede attack attempts and should trigger alerts.
- Matching logs with threat intelligence significantly reduces response time.
- Manual log reviews provide valuable insights, but automated detection is critical for early action.

#### Recommendations
Implement automated alerting for:
- Shellshock signatures
- Excessive 404 or 200 requests per IP
- Enable real-time ingestion and correlation of threat intelligence data.
- Enforce stricter WAF rules and rate-limiting policies.
- Apply CAPTCHA or bot filtering for suspicious user-agent behavior.
- Regularly review access logs and update detection rules quarterly.
- Educate DevOps and security teams on emerging exploit vectors.

## What Does the Enterprise Do Next?

### Synthesize the Investigation and Its Implications

The investigation revealed that the web application was actively being probed and targeted by:

- Exploit attempts (e.g., Shellshock via user-agent injection)
- Reconnaissance scans (high `404 Not Found` errors)
- Bot-driven scraping or brute-force activity (high `200 OK` volume)
- Known malicious IPs (matched via threat intelligence lookup)

These findings indicate a combination of opportunistic and targeted threats, pointing to weaknesses in real-time detection, rate-limiting, and external threat feed integration.

### Remediation Plan

#### 1. Technology Controls
- Implement automated detection rules in the SIEM for:
  - Shellshock-style payloads
  - Abnormal HTTP status patterns
  - Request spikes from a single source
- Integrate live threat intelligence feeds with automated blocking.
- Strengthen WAF (Web Application Firewall) rules to block injection and high-volume scans.
- Apply CAPTCHA and rate-limiting to deter scraping or brute-force behavior.

#### 2. Infrastructure Hardening
- Patch all vulnerable services, especially Bash-based systems.
- Remove or protect endpoints frequently hit during 404 scans.
- Configure Apache to throttle or block abusive IPs.

#### 3. Security Operations Improvements
- Define alert severity levels and build triage SOPs.
- Convert this incident into a reusable threat hunting playbook.
- Enrich log pipelines with geo-IP, ASN, and threat metadata.

#### 4. Organizational Resilience
- Train SOC and DevOps teams on emerging exploit signatures.
- Conduct red team/blue team exercises to test readiness.
- Update internal security policies to reflect post-incident learnings.

#### 5. Long-Term Monitoring and Audit
- Establish periodic audits of Apache logs, WAF policies, and detection rules.
- Deploy anomaly detection tools for ongoing behavioral monitoring.

### Outcome

By implementing these remediations, the enterprise will:

- Improve time-to-detection and response to real-time threats.
- Reduce attack surface and exploitability of public-facing systems.
- Protect customer trust and ensure long-term business continuity.
