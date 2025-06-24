# Cloud Security Monitoring

## 📝 Activity

This activity simulates a security investigation of AWS infrastructure. The analyst identified key security misconfigurations in region access, S3 policies, and ACL entries.

### AWS Region Usage

**Query:**

![AWS Regions](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e7eae27f-33c3-4dfc-86c6-0db4a86f2ce8)

_Extracts AWS region activity from logs._

    _sourceCategory=*AWS* awsregion 
    | json auto

![Non-US Regions](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ff958c91-16ab-474f-9521-a7eab4ad3727)

_Filters for non-US region activity._

    _sourceCategory=*AWS* awsregion 
    | json auto
    | where !(awsregion matches "*us*")

![Account-Level Region Activity](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/7bbc1f81-d2f7-41c6-b280-94d240ae2f99)

_Identifies user activity in unauthorized regions._

    _sourceCategory=*AWS* awsregion 
    | json auto 
    | where !(awsregion matches "*us*") 
    | where !(isNull(awsregion)) 
    | count by %"userIdentity.accountId", %"userIdentity.userName", awsregion 

### Vulnerable Network ACL Entries

![ACL Entry Creation](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/62d89e49-7ed9-4090-9bc3-e8ed4ad87800)

 _Detects when new ACL entries are created._

    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"

![Allow ACL Rules](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/6d86333d-0bae-4553-ad3c-34fc11faa224)

_Identifies ACL entries that allow all traffic._

    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"

![Full Port Range ACLs](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/fa5c0398-95c2-4a23-b9fc-158370592045)

_Flags ACLs allowing traffic on all ports (0-65535)._

    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"
    | where %requestParameters.portRange.from = 0 and %requestParameters.portRange.to = 65535

![Open CIDR ACL Rules](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/b2546e7b-7442-4eb0-85b2-fa0b061f07d3)

_Lists dangerous ACLs open to all IPs and ports._

    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"
    | where %requestParameters.portRange.from = 0 and %requestParameters.portRange.to = 65535
    | count by eventname,%requestParameters.ruleAction,%requestParameters.portRange.from, %requestParameters.portRange.to, %"requestParameters.cidrBlock"

## ⚠️ Threat Simulation

### SOC Analyst Response Process

1. **Detection**: Identified suspicious AWS activity and ACL rules.
2. **Analysis**: Queried CloudTrail logs for region and network access anomalies.
3. **Triage**: Prioritized alerts based on risk level and exposure potential.
4. **Escalation**: Flagged dangerous misconfigurations to DevOps/Cloud teams.
5. **Remediation Advice**: Recommended access restrictions and policy audits.

### 🚨 Alert Criticality

| Alert                                  | Description                                                  | Criticality |
|----------------------------------------|--------------------------------------------------------------|-------------|
| **Non-US Region Activity**             | Indicates misconfigured or unauthorized access.              | 🔶 Medium    |
| **S3 Access Mismanagement**            | Potential for data exposure via misconfigured roles.         | 🔴 High      |
| **Overly Permissive Network ACLs**     | Open port ranges to all IPs expose infrastructure.           | 🔴 High      |

---

## 💼 Business Implications

### 🔍 Impact on the Business

- **Compliance risks** (e.g., GDPR, HIPAA, SOC 2)
- **Service disruption** due to unauthorized access
- **Reputational damage** in case of data leak or breach

### 📉 Short-Term Risks

- Data exfiltration through open ACLs or S3 buckets
- Unauthorized infrastructure changes
- Emergency remediation causing service interruptions

### 📈 Long-Term Risks

- Persistent threats due to poor IAM practices
- Regulatory fines and increased audit scrutiny
- Reduced customer confidence in cloud security

## 🛍 Enterprise Actions

### 🧹 Synthesize the Investigation & Its Implications

- **IAM access**, **network policy misconfigurations**, and **region drift** expose critical flaws.
- Highlights lack of enforcement for cloud governance and security baselines.

### 🛠 Holistic Remediation Plan

| Action Item                                          | Team                    | Priority | Status        |
|------------------------------------------------------|--------------------------|----------|---------------|
| Enforce AWS SCPs for region control                  | Cloud Governance         | High     | 🔄 In Progress |
| Audit IAM permissions for overprivileged users       | IAM Security Team        | High     | ⏳ Planned     |
| Remove wide-open ACL rules (0–65535, 0.0.0.0/0)      | Network Engineering      | High     | ✅ Complete    |
| Enforce S3 bucket policy best practices              | Cloud Platform Team      | High     | 🔄 In Progress |
| Deploy AWS Config Rules for policy monitoring        | Cloud Security Team      | Medium   | 🔄 In Progress |
| Launch AWS security training initiative              | Security Awareness Team  | Medium   | ⏳ Planned     |

---

## 🔗 References

- [Kaspersky – What is Cloud Security](https://usa.kaspersky.com/resource-center/definitions/what-is-cloud-security)  
- [AWS S3 Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html)
