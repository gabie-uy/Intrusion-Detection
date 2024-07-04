# User Security Monitoring

### Brute Force

- “A brute force attack is a hacking method that uses trial and error to crack passwords, login credentials, and encryption keys. It is a simple yet reliable tactic for gaining unauthorized access to individual accounts and organizations’ systems and networks. The hacker tries multiple usernames and passwords, often using a computer to test a wide range of combinations, until they find the correct login information.” Defined by Fortinet. 

- In the alerts indicated in the figures below, they show the history of the failed and accepted passwords during a specific period. There is a very short gap between each log indicated in the logs which is a common characteristic in determining brute force attacks due to its trial-and-error actions. When trial-and-error is done using a program or software, passwords can immediately be done quickly. The criticality for this attack may not be as high as other, more specific types of brute force attacks, however, if logs show that there have been accepted log ins without the company employees being aware, immediate action should be done do remove or reset these accessed accounts from the system of the organization to avoid compromise or lessen the compromise. Compromised accounts can affect the business if the attackers/intruders have edited or played around with the information they can access. If the company has back-up files of all their information, they will not lose anything and can restore files back, but they can assume that the attackers possibly have a copy of their files as well that they can use for any purpose. This affects the trust the customers would have with the organization but does not affect the hassle for both parties to revive everything.

### Password Spray

- “A password spraying attack is a type of brute force attack that involves the attacker using one specific password to try and access many different accounts. This type of attack commonly works on user accounts with default passwords.” Defined by OWASP.

- The investigation shown through the screenshots below show the number of failed password attempts, these indications show each address having at least an attempt in accessing a user’s account. As an analyst, I would be checking accounts with many numbers of attempts, once I am able to figure out the account, I will temporarily block the account and notify the user if he/she is the one trying to log into the account due to too many numbers of attempts. Allowing them to receive a notification would help them be aware that the accounts are being watched, and if they are the ones trying to access the account then they can tell the security team that it is them. If they do not claim anything, then at least the account has been blocked rather than leaving the account open, still trying to be accessed by someone who is not the owner. For businesses, having protocols and rules run into the systems and employees would help them prevent unnecessary account access, and keep their information and system secure. However, with issues like that, it might be hassle for customers to have to wait for a response from the security team if they forgot the access to their account. Good security makes convenience much harder to aim. Reputation by keeping the accounts safe good for the company, however, it is also common for many people to complain about the processes of keeping accounts and information secure like the situation mentioned previously. Accounts being accessed by attackers can cause severe damage to the company depending on the purpose of their attack. Attackers can exploit accounts to try and access privileges in the company’s system that can cause disruption, malfunction, and shut down of the system which will lead to the company spending a large amount of money trying to solve the issue or worse, lose the business. 

### Threat Intelligence

- “Threat intelligence is data that is collected, processed, and analyzed to understand a threat actor’s motives, targets, and attack behaviors. Threat intelligence enables us to make faster, more informed, data-backed security decisions and change their behavior from reactive to proactive in the fight against threat actors.” Defined by Crowdstrike.

- The images below present a high malicious attack regarding the attack involved under the same IP address. The characteristics and activities of the specific user is indicated as a threat in the system which shows similar behaviors with each attack. As an analyst, I would be checking the behaviors of the employees to see the similarities to understand the daily action of the employees. This can help in determining an attack because of the difference, no matter how minimal the changes are. The criticality of this would depend on the attack pattern done by the attackers on the system. Since threat intelligence is about the collected, processed, and analyzed data, there will be different patterns and attacks that will show up which would present different attack hence, different levels of criticality due to the type of attack. The detections found in the images shown below, indicate a high criticality due to the attack found being malware related, ransomware to be specific. This affects the company badly because their data and information can be locked (encrypted) and stolen. Their system will be compromised, and they will lose access to it. Attacks like ransomware should be addressed immediately because it can gravely disrupt and take down a business either due to loss of data, or loss of money to resolve the ransomware. Customers will have all their information stolen as well.

- It is important for customers and employees to be reminded to keep their accounts secure to avoid mishandled information. Trainings and awareness to small precautions will allow safety and convenience to work as one. All individuals must not use common passwords for accounts to have stronger protection against malicious users. With many types of attackers to use, there have become many possible ways and outcomes for accounts. It is always better to change your password from time to time. It is also best to steer clear from using the same passwords in many accounts and platforms to avoid them all being hacked. Everyone should also have multiple emails and separate each of those, as well as using different passwords, to safely protect each user’s accounts.

## Figures

#### Brute Force
 
(_sourceCategory=Labs/OS/Linux/Security)
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/b1bcc3c3-de4f-4f63-abb6-47bf0f4bcba5">

(_sourceCategory=Labs/OS/Linux/Security )
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port
| where status = "Failed"

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/78beff6b-8b77-40eb-9e78-27b983e2796b">

(_sourceCategory=Labs/OS/Linux/Security )
| timeslice 30m
| parse ": * password for * from * port * ssh2" as status,user,ip,port
| where status = "Failed"
| count by _timeslice, user,status,ip,port
| where _count < 50
| sort by _count

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/fa505689-267a-49d4-b1f8-dbd60b8b6403">

#### Password Spray
 
    (_sourceCategory=Labs/Okta)
    | timeslice 15m
    | where %"outcome.result" = "FAILURE"

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ee0afcbd-3a57-4076-9721-b80134827204">
 
    (_sourceCategory=Labs/Okta )
    | timeslice 15m
    | where %"outcome.result" = "FAILURE"
    | count_distinct(%"actor.alternateId") group by _timeslice, %"client.ipAddress"

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/52f54ef9-6e1b-4abd-ae9e-b182a42684ba">
 
    (_sourceCategory=Labs/Okta)
    | timeslice 15m
    | where %"outcome.result" = "FAILURE"
    | count_distinct(%"actor.alternateId") group by _timeslice, %"client.ipAddress"
    | where _count_distinct>5
    | sort by _count_distinct

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1358a71d-2260-48b7-944a-dba26854513a">

#### Threat Intelligence
 
    ((_sourceCategory=Labs/Azure/AD))
    | where operationname = "Sign-in activity"

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/5ee2bf38-21bb-4b96-8dc5-f80aa38801a9">
 
    ((_sourceCategory=Labs/Azure/AD))
    | where operationname = "Sign-in activity"
    | %"properties.ipAddress" as ip_address

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/be9b8445-85b9-4a6c-b2ea-41657c17f2a7">

    ((_sourceCategory=Labs/Azure/AD))
    | where operationname = "Sign-in activity"
    | %"properties.ipAddress" as ip_address
    | lookup type, actor, raw, threatlevel as malicious_confidence from sumo://threat/cs on threat=ip_address
    | json field=raw "labels[*].name" as label_name
    | replace(label_name, "\\/","->") as label_name
    | replace(label_name, "\""," ") as label_name
    | where type="ip_address" and !isNull(malicious_confidence)
    | if (isEmpty(actor), "Unassigned", actor) as Actor
    | count by %"properties.userPrincipalName", ip_address, malicious_confidence, Actor, label_name

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1ad2d07d-ebd9-4007-8797-a016a57307d8">

## References
•	https://www.fortinet.com/resources/cyberglossary/brute-force-attack
•	https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/
•	https://owasp.org/www-community/attacks/Password_Spraying_Attack
