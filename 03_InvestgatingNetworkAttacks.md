# Investigating Network Attacks

## Abstract

There are many types of network attacks in existence today. The public often uses networks to access the Internet. The web is a broad environment with many people and devices involved. 
Users can share files and data and even communicate with society as everything is connected to a network, no matter how simple. With the vast network, anyone can use it for many things. 
Therefore, it can be vulnerable to users with malicious intent who would want to exploit the network to achieve their goals. 
These malicious actions can involve infiltrating organizations and businesses through private and public networks to steal information or disrupt their services. 
Over the years, there have been attacks that were discovered. Some of these attacks were the foundation of the new and future attacks that will eventually (but hopefully not) come. 

**Three types of network attacks will be discussed in this paper:** 

  1. Port Scanning,
  2. Worms – Slammer, and
  3. Command and Control – Zeus. 

*The report will discuss the possible ways to respond to these threats, the criticality level, how it will impact the business, and how the enterprise will move forward and handle threats.*

## Three Network Attacks

### Port Scanning
- ```Port Scanning``` is a technique hackers use to discover ports in a system, find specific ports that are active, and use them as something like a door that was left open – a vulnerability. These scanners can inform users of the operating system it uses, services running on them, network services that require authentication, an active firewall, and if anonymous logins are allowed. The attack can scan a specific range of open ports on a system. There are three ways to classify a port: open, closed, and filtered. Open ports would typically indicate it is available to requests, closed ports would suggest no activities or applications are listening, and filtered ports mean that congestion or a firewall is blocking the transmission.
- A successful port scanning attack would show that devices have slowed down, lost, and received unknown files. An analyst may be able to discover port scanning attacks by checking packet transmissions. Many ports are explicitly assigned for different purposes; it would be partially distinguishable for certain packets and IP addresses to be recognized if they came from addresses unknown to the organization. The criticality of these packets would vary depending on what port they were trying to access, the number of packets arriving simultaneously, and if a port got invaded. Logically, compromised, or vulnerable ports should be the first to be handled by the cybersecurity team. Next would be packets arriving rapidly that are unknown. Having a system get compromised would slow down the business, and depending on how bad the attack was, the company would have problems with their systems slowing down and complaints from users. In the long-term, it would affect an organization's information and connection to the Internet, which would cost them money to be able to replace those systems. It might have affected the company's reputation due to errors and a slow system. It would be best if the company would invest in software and systems focusing on the security of the ports. The security team should constantly update those systems and check them for any suspicious activity to be able to remedy the ports that may get affected immediately. Firewalls are the most necessary to protect the ports and prevent unauthorized system access. TCP wrappers should be implemented as well to be able to deny or accept transmission by determining the IP address and domains.

### Slammer Worm
- Worms have been one of the first threats to exist in the cyber industry. Worms have infected many devices over the years, becoming a basis for many other threats. A ``computer worm`` is an attack that replicates itself to be able to steal, delete, modify, and even deplete the device's resources and system. They can come from emails, attachments, and messages. A specific type of worm famously leveraged on the Microsoft SQL Server many years ago is what they call Slammer Worm. The Slammer worm targeted the MS SQL Server by repeatedly and quickly sending significant amounts of payload to any IP address until it caused the server to be in denial-or-service and shut down.
- The easiest way to determine whether there is an attack on the system would be the number of ping requests from a source. Since it is normal for Slammer worms to come in rapidly, it could be assumed that there would be many attempts to ping the destination. Depending on the number of attempts, it would be easier to say that the level of criticality would be above normal only because the system may be protected. Still, it is a sign to double-check the security of all ports and systems to avoid the possibility of a successful attack. In the short term, if an organization can figure this out immediately, it will know which systems are trying to be accessed. It would allow the organization to swiftly check, find, and add other ways to protect their system so that they will not experience things like DoS. In the long term, DoS would be a significant issue for them as it would cause the system to fluctuate and stop work. When business is interrupted, they can lose a lot of money and have a bad reputation for errors that cause DoS. To avoid these, organizations can ensure they have the proper security protocols and software to protect and prevent their systems from vulnerabilities or attack attempts. Analysts should be aware of new patches and updates to avoid security flaws, as threats are also updating. Employees and everyone involved in the organization should be taught and aware of how to use their system's platforms and secure their accounts. Many attacks come from simple actions such as phishing. It would be efficient for companies to invest in software that protects users against attacks such as anti-malware, anti-virus, etc.

### Zeus Command and Control
- Specifically, ``Zeus`` is a type of malware that can install itself on a device. It directly attacks bank credentials and information. If a device gets infected, it will be added to a network full of botnets called ZBot or Zeus botnet that answers to commands from one control center. Zeus is used to spy on a user's keystrokes, login credentials, cookies and trackers, POP and FTP account information, and even HTTP forms to get bank information. This type of malware can be passed around disguised as a code sent from a fake website, an attachment on an email, etc. –like any other threat. Sometimes, a user does not know they have a botnet in their system. There are botnets placed on a device waiting to be controlled by the command center, which then would trigger a DDoS when activated thus, disrupts the system.
- There are ways a user can distinguish if their device has been infected by malware. Systems tend to slow down suddenly; sometimes, unknown applications are seen without your knowledge of having them there and using up the system's power which would then lead to the immediate power loss of the device. The simplest ways would be bank activity, meaning someone has figured out the user's bank credentials and accessed their bank account. In levels of criticality, the highest priority would be dealing with anything related to the user's bank account, while the rest can follow afterward. However, immediate action should be taken when a system slows down or contains different applications without the user's knowledge. Users could install a VPN to protect their IP addresses to prevent these attacks. Investing in add-blockers and anti-malware software is also good to avoid pop-ups and unnecessary websites. Lastly, it is to be knowledgeable of credible emails and attachments. Phishing is another way an attacker can send malicious code into a device, and if accessed, it could lead to severe damage and expenses. Companies should have sessions to teach and update their employees and co-workers about threats such as phishing and ads to avoid sudden disruptions and loss of information. Losing credentials could lead to a user losing money and access to their devices, but in the long haul, organizations may get their system and private work information stolen as well. Client's and user's information may get compromised, which could lead the company to possible long-term issues. The trust of the users would be lost too.
	
### References
- Higgins, M. (2022, June). How to protect yourself from the zeus virus. NordVPN. Retrieved September 2022, from https://nordvpn.com/blog/zeus-virus/ 
- Kaspersky. (2022, August 12). Zeus virus. usa.kaspersky.com. Retrieved September 24, 2022, from https://usa.kaspersky.com/resource-center/threats/zeus-virus 
- Keith ChewKeith’s appreciation for computing and processes originates from working with his first personal computer in 1982. (2021, September 28). Malware of the day - zeus. Active Countermeasures. Retrieved September 24, 2022, from https://www.activecountermeasures.com/malware-of-the-day-zeus/ 
- Rountree, D. (2011). Security for Microsoft Windows System Administrators, i-ii. https://doi.org/10.1016/b978-1-59749-594-3.00012-0 
- What is a computer worm and how does it work? (2018). Retrieved September 24, 2022, from https://us.norton.com/blog/malware/what-is-a-computer-worm# 
- What is a port scan? how to prevent port scan attacks? Fortinet. (n.d.). Retrieved September 24, 2022, from https://www.fortinet.com/resources/cyberglossary/what-is-port-scan 
- What is Port Scanning? Datto Networking. (n.d.). Retrieved September 25, 2022, from https://www.datto.com/blog/what-is-port-scanning
  
## Figures

<div align="center">
  
  #### Figure 1.1: Port Scanning – Threat analysis
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f362e47e-4ce0-4976-b892-3c0b1ef86520)
      
  #### Figure 1.2: Port Scanning – Threat analysis
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/d4cf99aa-cb4e-4e69-b059-c3c3e546aa8d)
      
  #### Figure 1.3: Port Scanning – Threat analysis summary
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/5a66c611-02d4-474e-a04a-ea366ac36016)
      
  #### Figure 2.1: Slammer Worm – Hex dump of a packet
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/77913cbc-8f6b-4250-b276-15a01615e8ed)
       
  #### Figure 2.2: Slammer Worm – End points of a packet
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/2535d5fe-c1c4-425c-8484-058e3d544c48)
       
  #### Figure 2.3: Slammer Worm – Threat analysis of a packet
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/68cbc358-4d8b-47ba-a3bd-967736cdec50)
      
  #### Figure 3.1: Zeus Command and Control – Packets of the destination port
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/850101ff-df30-4937-b73d-08ae87cd9b05)
       
  #### Figure 3.2: Zeus Command and Control – Packet length
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e4c6d09b-2f9a-4996-ac0f-2d3175f32b55)
       
  #### Figure 3.3: Zeus Command and Control – HTTP requests
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e3a95999-2bca-4025-9646-49c73aefe0f3)
       
  #### Figure 3.4: Zeus Command and Control – HTTP request
  ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/7478d416-6d64-4cfd-99f6-40df43094391)
  
</div>
