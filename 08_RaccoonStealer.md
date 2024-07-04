# Raccoon Stealer & RecordBreaker (Raccoon Stealer v2)

## Introduction

In 2019, a Ukrainian named Mark Sokolovsky and others not named created a malware-as-a-service called Raccoon Stealer. Telsy refers a malware-as-a-service (MaaS) as “the illegal lease of software and hardware for carrying out cyber-attacks.” Raccoon Stealer debuted in 2019 that is capable of stealing passwords, credit card numbers, email addresses, cryptocurrency addresses, and bank account details from its victims. To use this MaaS, customers (considered cybercriminals) could access this service for $200 per month or $75 per week. The Justice Department confirmed that Raccoon Stealer would arrive as phishing emails, such as fake messages about COVID-19. The victims who believe these emails and messages get malicious code installed on their devices.

Mark Sokolovsky was recently arrested in the Netherlands, and the service was later shut down in March 2022. However, the second version of the Raccoon Stealer existed again in mid-2022 July called RecordBreaker. In addition to the first version’s capabilities, RecordBreaker can download from the Internet or browser: login and password credentials, cookies, cryptocurrency wallets, and arbitrary files on a device. Much information stolen is from auto-fill data from logins, passwords, and activities. It is believed that more than 50 million pieces of stolen information were sold to the dark web marketplace.
 
**Figure 1 – An example of a Raccoon Stealer malicious email.**

### Capabilities

It is reported on The Hacker News that version two does steal not only cryptocurrency wallets but also attacks cryptocurrency-related browser plugins. These plugins sometimes hold wallet addresses, past transactions from other wallets, and recovery keys. The developers enhanced the malware’s ability to steal files regardless of the disk they reside in. It can also capture a list of applications installed on a specific machine. This could help the attacker to know what information and files reside in those applications that can be proven essential or unimportant.

One of the new capabilities included in the more recent version is the ability to capture screenshots from an infected system meaning these screen captures can be used for many purposes. An example mentioned by The Hacker News is that the attackers can watch their victims and capture situations like the checkout portion of an online shop, which would expose the user’s basic information, contact details, home/bill/work address, and credit card information together with the security code. Access to this information can allow the attacker to perform further malicious activities.

## Technological Methodology

### Exploitation

| Execution Process	| What the Raccoon Stealer Malware Does |
| --- | --- |
| Downloads WinAPI libraries | Uses kernel32.dll!LoadLibraryW |
| Gets WinAPI functions addresses	| Uses kernel32.dll!GetProcAddress | 
| Strings and C2 servers encryption	| Encrypts with RC4 or XOR algorithm, can be no encryption at all, or a combination of different option |
| Crash triggers	| CIS countries locale, mutex |
| System/LocalSystem level privilege check	| Uses Advapi32.dll!GetTokenInformation and Advapi32.dll!ConvertSidToStringSidW comparing StringSid with L "S-1-5-18"
| Process enumeration |	Uses the TlHelp32 API (kernel32.dll!CreateToolhelp32Snapshot to capture processes and kernel32.dll!Process32First / kernel32.dll!Process32Next).
| Connecting to C2 servers | Creates a string: <br> machineId={machineguid}{username}&configId={rc4_c2_key} <br> Then sends a POST request |
| User and system data collection	| The OS Bitness, Information about RAM, CPU, Applications installed in the system, Cookies, Autofill data, Autofill form data |
| Sending of collected data	| POST requests to C2. |
| Getting an answer from the C2	| C2 sends “received.”|
| Finishing operations	| Takes a screenshot(s), releases the remaining allocated resources, unloads the libraries, and finishes its work |

An analysis is discussed below with some images that possibly describe how Raccoon Stealer works – giving an idea of how it is used and how attackers exploit this service.

**These are the steps in the process of analysis:**

1. Loading Libraries

 ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a7602856-2272-47a7-8e0e-d2258ed16041)
  
Raccoon Stealer is dynamically loading needed libraries (WinAPI) using a ``kernel32.dll!LoadLibraryW`` and get addresses of WinAPI functions using ``kernel32.dll!GetProcAddress`` 

2. Decryption

 ![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/df1689be-cb76-4cf9-acb8-9c40ceef2b66)

Some strings are encrypted through RC4 and encoded into Base64; then, XOR is encrypted with a random key. Some examples of decrypted strings are:
``logins.json``
``\autofill.txt``
``\passwords.txt``
``formhistory.sqlite``

3. Command and Control Decryption

*RC4 encryption with further recoding to Base64*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/c10ca54a-af53-4c87-a3e9-53530352381e)

*Encryption with XOR*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/902472e9-0e6e-4f6d-9c3b-b51f2609660a)
 
4. Checking for Specific User Locale
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/8b62a824-34ea-4dfb-a818-11de2270652c)

Raccoon checks for a mutex – if it has been executed or rerun in the past. If there is an existing mutex in the past, the code will terminate; otherwise, it will create a mutex.

5. Privilege Level Check

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/065e428c-c867-45ca-909c-85725355e007)

After creating a mutex, the malware performs a System/LocalSystem level privilege check using Advapi32.dll!GetTokenInformation and Advapi32.dll!ConvertSidToStringSidW comparing StringSid with L “S-1-5-18”.

6. Process Enumeration

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/02780969-d353-427f-9bb7-8eb72e0f0f6d)

If the check shows that RecordBreaker has the privilege level it needs, it starts enumerating processes using the TlHelp32 API.

7. Connecting the Command-and-Control Server

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/fe2362e0-18f2-47d3-b59c-b9f649f2f608)

The malware will try to connect to the first Command-and-Control server it first discovers. If it cannot find one, it will terminate the program. For the malware to connect to a server, the program will send a POST request – it requests that a server accept the data enclosed – for the service to generate a string like machineId={machineguid}|{username}&configId={c2_key} or

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/c8b04683-247c-4c24-ab48-f50faa974f2d)

8. Service Steals Device Information

*Size of the primary monitor using ``user32.dll!GetSystemMetrics``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/753cc397-2f3d-4d57-87fd-e25153382290)

*GPU devices, using ``user32.dll!EnumDisplayDevicesW``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/cac0dabd-b279-4de9-b695-93e87c61a936)
 
*Display resolution using ``kernel32.dll!GetSystemWow64DirectoryW`` and comparing the last error code with ``ERROR_CALL_NOT_IMPLEMENTED``*
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/9e59dfc8-19c7-4c39-aa87-15439d784b56)

*RAM information via ``kernel32.dll!GlobalMemoryStatusEx``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f7e00da5-5f3f-4d81-8567-a1a6ef8ba089)
 
*User’s time zone by ``kernel32!GetTimeZoneInformation:``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/b694a205-7b78-4bae-807a-883991f3814f)
 
*OS version from the registry, using ``advapi32.dll!RegOpenKeyExW`` and ``advapi32.dll!RegQueryValueExW`` to read the value of the key ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows`` ``NT\CurrentVersion\ProductName``*
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/0e438c5a-547f-4b74-98e2-cea020f5ddd3)

**Vendor of the CPU using ``asm-instruction __cpuid:``**

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/adcc3055-ecef-4863-b692-4522cdbb6078)

*CPU cores number with ``kernel32.dll!GetSystemInfo``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a5c28783-eb06-4859-b79f-c0d9e8844a8b)
 
*User’s default locale info requesting ``kernel32.dll!GetUserDefaultLCID`` and ``kernel32.dll!GetLocaleInfoW``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ac1da087-3d60-4719-a7e0-e81a214474bc)

*Data about installed apps from the registry using ``advapi32.dll!RegOpenKeyExW``, ``advapi32.dll!RegEnumKeyExW``, and ``advapi32.dll!RegQueryValueExW``*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ac041c80-978e-4cc3-8b27-de58c3c38119)

This is where the malware is ready to access user information. Raccoon Stealer is loading previously downloaded legitimate third-party libraries.

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/6c2a6d40-bcbd-4642-9ebe-134b2f586971)

Raccoon Stealer gets function addresses from the newly loaded modules.

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/78a02105-5f58-49e6-a440-cf394a705536)
 
9. Stealing User Data

*Cookies*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/95dae01b-fc91-4c69-bff6-5da4c657e900)
 
*Autofill Data*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/44ceacc7-ccb7-4800-a6c2-ac7c84a1f205)

*Autofill Form Data*

It attempts to open the ``formhistory.sqlite database:``

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/c38fe851-6789-4421-97c4-fd13fa83f3ec)

The program tries to decrypt the data from that database using the Зnss3.dll!PK11SDR_Decrypt method.
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/8980a7e7-0a67-4086-ba9d-ad15bbf073fc)

Data is then concatenated, then sends POST requests to Command-and-Control servers again.

*SystemInfo POST request*

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/5a594098-f509-4267-960d-28999f78e914)

*UserInfo POST request*
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/77003883-b7f5-4d2d-be68-8a603856077f)

*Crypto Wallets and Data* 

Crypto wallets are found through filters and templates received from the configuration.

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/129dd122-fd1f-408b-89b6-35ba6f7b3a6d)
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ded5f350-347b-4d75-ae0d-def175613829)
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/07af954a-9097-4ce6-9dba-b82236597490)

*Custom Files*

The service now looks for arbitrary files that can be useful for exploitation from directories specified.
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/63821e9a-2eaf-4ff6-9736-799a917c214d)
 
*Telegram Files*

The service then looks for files from Telegram messenger.
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/3de28dcf-5a13-4b5c-87fc-7d0c06ead173)
 
After the entire process, the malware-as-a-service takes a screenshot or screenshots of the user’s environment.
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/6d75080f-44c7-42b9-bd8f-65cac39c1854)
 
If extra commands are not yet executed, the program will continue until it is finished and will end by releasing the remaining allocated resources.
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f79a2dd4-543c-47d2-b980-3d2914e8663d)
 
#### Description of the Malware

<img width="633" alt="Screenshot 2024-07-04 at 1 03 11 PM" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/43b711ff-49c5-4540-96fe-16af5fcdb686">

## Mitigations & Preventions
1.	User education – Where the organization, may it be any user, should learn the basics of safety and security protocols on emails, text messages, and account care.
a.	Do not open attachments from emails that are not familiar.
b.	Double-check the email source or message and authenticate if the contents are safe.
c.	Clarify if the requested file or attachment is official before opening emails; this also goes for links attached.
2.	Use anti-malware/anti-virus software – Keep software and systems up to date; be aware of new updates or patches to battle specific threats and vulnerabilities.
a.	Automated malware scanning
b.	Signature-based detection
c.	Behavior-based detection
d.	Machine learning-driven detection
3.	Use complicated passwords – A unique password will deter password hacks that can be used to access the accounts and systems.
4.	Vulnerability management – Addressed vulnerabilities should be discussed; install, download, or update software and systems.
5.	Security policy implementation – Specific policies and measures must be outlined and implemented in the entire organization.

## Conclusion

### Remediation

The Justice Department created a website to find out if a user’s email address was found in the repository of the service: https://raccoon.ic3.gov/home. There are also multiple organizations and tools where a user can report malicious activity spotted online; some examples would be Google, the FBI, and US Computer Emergency and Readiness Team (US-CERT).
Some common strategies for remediation can be:

1. Shutting down services used by malware
2. Disabling infected system components
3. Blocking access to infected networks
4. Anti-virus software
5. Guided malware remediation
6. Rebuilding infected digital assets 

Some recommendations for remediation are proposed by the SpecOps begin with end-user knowledge. End-user knowledge is where companies and organizations are obligated to teach their employees about phishing, social engineering, and other simple but common attacks to avoid incidents of them giving their personal information away that may be used to access their data compromise the information of the business.

Another suggestion was a 3-2-1-1 backup plan where the user has two backups online, one offline, and one on an encrypted immutable device. 

The Zero-Trust remediation plan involves two categories: The first is Least privilege. This involves granting users the least amount of access needed for their work rather than granting permissions based on the implicit trust inherited from the organization. The second zero-trust is De-Parameterization. De-parameterization addresses the fact that remote work and remote applications have distributed the boundaries of a company beyond its physical walls.

The easiest way to protect a user’s information is to always update patches and software of devices and applications.

In conclusion, malware (or cyberattacks) is unavoidable in a way where it will always exist and be developed overtime in correlation with cyber security as a service. However, this also indicates that cyberattacks are avoidable through proper data security and protocols when the specific user is always aware and wary of threats and vulnerabilities. Raccoon Stealer is just one of the services that will try to attack many users, but as observed in the process of how to use it, it also shows that it is dependent on weak services, passwords, and vulnerabilities of systems and accounts. It is possible to avoid getting attacked by always being overprotective of information and being organized and updated with news regarding attacks.

## References
- “Breaking down the most effective malware remediation processes” RSI Security, RSI Security, 30 Mar. 2022, https://blog.rsisecurity.com/breaking-down-the-most-effective-malware-remediation-processes/
- Giuseppe, Claudio. “Malware-as-a-service (Maas): What it is and why it is (very) dangerous” Telsy, Telsy, 05 Oct. 2022, https://www.telsy.com/malware-as-a-service-maas-telsy/#:~:text=Malware%2Das%2Da%2DService%20(MaaS)%20refers%20to,account%20in%20an%20online%20platform.
- “Inside raccoon stealer V2” The Hacker News, The Hacker News, 02 Nov. 2022, https://thehackernews.com/2022/11/inside-raccoon-stealer-v2.html
- Kan, Michael. “US Indicts Ukrainian for ‘Raccoon Stealer’ Malware That Hit Millions of Computers.” PCMAG, PCMag, 25 Oct. 2022, https://www.pcmag.com/news/us-indicts-ukrainian-for-raccoon-stealer-malware-that-hit-millions-of-computers#:~:text=Raccoon%20Stealer%20emerged%20in%202019,into%20installing%20the%20malicious%20code. 
- “Raccoon Stealer 2.0 malware analysis” ANY.RUN Blog, ANY.RUN Blog, 30 Aug. 2022, https://any.run/cybersecurity-blog/raccoon-stealer-v2-malware-analysis/?utm_source=hacker_news&utm_medium=article&utm_campaign=raccoon&utm_content=blog
- “Racoon stealer is back - how to protect your organization” The Hacker News, The Hacker News, 25 Jul. 2022, https://thehackernews.com/2022/07/racoon-stealer-is-back-how-to-protect.html
- PitchKites, Max. “ Ransomware Prevention Best Practices.” SpecOps, SpecOps. 04 Dec. 2022, https://specopssoft.com/blog/ransomware-prevention-best-practices/?utm_source=thehackernews.com&utm_medium=referral&utm_campaign=na_2022_hackernews 
