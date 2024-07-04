# Investigating Web Application Attacks

    sourceCategory=Labs/Apache/Access

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/3582db80-6e0a-4460-adb9-4ece0ac0468f)
 
     _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a058174a-f75e-4050-8db9-8bb58410eb7d)

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | count by src_ip, country_name, organization, user_agent
    | sort by _count

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a6457449-6229-466d-87f0-a9462f9a33cc)

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | where user_agent matches "*() { :; }*"
    | count by src_ip, country_name, organization, user_agent
    | sort by _count

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/853f2fa0-09da-43ee-8ea3-9ba403d9f501)

    _sourceCategory=Labs/Apache/Access
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by src_ip, country_name, organization, user_agent, status_code
    | sort by _count

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/c53cdfb3-c7ba-4e65-8cbd-e4b9af2556b2)

    _sourceCategory=Labs/Apache/Access 
    | timeslice 60m 
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by _timeslice, src_ip, country_name, organization, user_agent, status_code 
    | sort by _count 
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/1cebe28d-ede1-43ef-9d9a-2bcb15de70dc)

    _sourceCategory=Labs/Apache/Access
    | timeslice 60m
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "404"
    | count by _timeslice, src_ip, country_name, organization, user_agent, status_code
    | where _count > 20
    | sort by _count 
 
![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/a3aa4b1b-0c66-4f14-a7a0-c907e19b6cb8)

    _sourceCategory=Labs/Apache/Access 
    | timeslice 1m 
    | lookup latitude, longitude, country_name, region, city from geo://location on ip = src_ip 
    | lookup asn, organization from asn://default on ip=src_ip
    | where status_code = "200"
    | count by _timeslice, src_ip, country_name, organization, status_code 
    | where _count > 50 
    | sort by _count 

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/f54006d5-0336-4f88-8387-66e5912be0ca)
 
    _sourceCategory=Labs/Apache/Access
    | lookup type, actor, raw, threatlevel from sumo://threat/cs on threat=src_ip

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/769498db-8214-4015-ab76-f2b4cd57bb2b)

    _sourceCategory=Labs/Apache/Access
    | lookup type, actor, raw, threatlevel from sumo://threat/cs on threat=src_ip 
    | where !(isNull(threatlevel))

![image](https://github.com/gabizzle/Intrusion-Detection/assets/67624149/8a4d37c4-a156-4c9a-8776-9973c014c7f6)

## Threat Simulation 
### If you were responding to each of the alerts as a SOC Analyst describe the process which you would take to investigate the alert.
If I were a SOC analyst, I would check past threats to see if there are similar behaviors to what is seen. Comparing the past and present may give some answers to the behaviors seen. If there is a similar behavior in the past to what is seen now, it may be quicker and easier to be able to battle and prevent it from getting worse. If there are no similarities, the behavior can be studied and double-checked to see if it is a threat. However, it is always better to think it is a false positive threat than to ignore something out of the ordinary. Good security tools with advanced analysis on things like traffic and IP will help. Just like for IP addresses, it is possible to check the IP address reputation and determine immediately if it had past malicious activities. 

### What criticality would you assign the alerts to? Should they all be treated the same? 
When a threat occurs, priority levels can help prioritize which threat to attack/defend from first. It will also help which vulnerabilities need to be strengthened. I do not think they should all be equally prioritized. Like the crawling detection/crawlers, I think they should be dealt with first because they can look through vulnerabilities and do malicious intent on them the moment they spot a vulnerability. It explains that it can run commands once an attack can enter a vulnerability. An example of limiting requests, like in the exercise, shows that a fast number of visits is very unusual for a person. Therefore it should be immediately addressed that there is suspicious activity going on.

### The Business Implications of These Results 
Explain how these detections impact the business, what are the short term and long-term risks presented?
In the short term, it would affect business in a way that would affect work hours and cause minor malfunctions in the system, inaccurate information, and affect users. In the long term, it would not help the business’s reputation because of the spreading of errors and threats to the information they receive. The chances of having fewer customers will affect them because of their bad reputation, and it can/will lead to the loss of the business because of the mishandling of the situation.

### What does the enterprise do next?
Synthesize the investigation and the implications for providing holistic remediation to the incident 
I think the enterprise can use these errors as a stepping stone to creating a better and more secure environment to avoid these attacks. Investing in security tools and threat detectors would be best to lessen, if not altogether, avoid cyber-attacks. Security features like CAPTCHA will slow things down and complicate penetrating or entering accounts, etc., by bots. As tough as tedious, it is best to be able to update and change HTML markups and easily distinguish fake websites from original ones. This can avoid scrapping on websites. Investing in efficient and advanced security tools will add better protection away from SOC analysis itself. This will allow analysts to focus on other more challenging, more complex attacks (if there are any) and focus on more work to watch.
