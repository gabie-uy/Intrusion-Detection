# Cloud Security Monitoring

- Cloud security focuses on the security of data in cloud computing systems. Cloud computing systems lets organizations and businesses store data, applications, and platforms in an online infrastructure. This is used by small companies, medium, and the enterprise. It is important to secure the cloud because of the many organizations that depend on such system.

- Defined by Amazon, “Amazon Simple Storage Service (Amazon S3) is an object storage service that offers industry-leading scalability, data availability, security, and performance. Customers of all sizes and industries can use Amazon S3 to store and protect any amount of data for a range of use cases, such as data lakes, websites, mobile applications, backup and restore, archive, enterprise applications, IoT devices, and big data analytics. Amazon S3 provides management features so that you can optimize, organize, and configure access to your data to meet your specific business, organizational, and compliance requirements.” S3 offers different storage management features that help organize data. They also offer different access management features that help in securing and managing the system.

- As a SOC analyst, I would ask the company if they can provide common protocols to use and have trainings to provide to be able to learn and understand certain scenarios. Learning these protocols and experiences of past analysts or current analysts can help to mitigate errors that can occur with plugging in wrong inputs and codes. Experiences are hard to learn and it would be easier to ask for help from seniors or those who have dealt with such situations in the past. Open-sources may help but is not initially ideal in the workplace. However, it may be able to help in giving an idea due to the similarities many companies experience. 

- I believe that the criticality of access management problems should be the top priority. This will allow unauthorized access to be able to control majority of the system. They can view, edit and “manage” the entire enterprise because of having access to the system. To be specific, it is more important to begin assessing and checking administrative accesses that allows users to be able to control and command majority of the system, as compared to those roles below the administrative department. I would believe that roles below the administrative department would have less impact in the company as a whole due to less access in the system.

- In conclusion, mitigating these attacks will always come with knowledge and constant learning and development to understand how to tackle these attacks. It is a constant chess like game where both entities or parties continue to find a new way to defeat the opponent. New attacks would require new ways to secure, and conquer them –they are inevitable but not impossible to address.

## Figures
### AWS Regions
 
    _sourceCategory=*AWS* awsregion 
    | json auto 

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/e7eae27f-33c3-4dfc-86c6-0db4a86f2ce8">
     
    _sourceCategory=*AWS* awsregion
    | json auto
    | where !(awsregion matches "*us*") 
    
<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/ff958c91-16ab-474f-9521-a7eab4ad3727">
     
    _sourceCategory=*AWS* awsregion | json auto
    | where !(awsregion matches "*us*") | where !(isNull(awsregion)) 
    | count by %"userIdentity.accountId", %"userIdentity.userName", awsregion 
    
<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/7bbc1f81-d2f7-41c6-b280-94d240ae2f99">

### Vulnerable Network ACLs 
 
    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    
 <img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/62d89e49-7ed9-4090-9bc3-e8ed4ad87800">
       
    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"
    
<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/6d86333d-0bae-4553-ad3c-34fc11faa224">
     
    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"
    | where %requestParameters.portRange.from = 0 and %requestParameters.portRange.to = 65535
 
<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/fa5c0398-95c2-4a23-b9fc-158370592045">
    
    _sourceCategory = *AWS*
    | json auto
    | where eventname = "CreateNetworkAclEntry"
    | where %requestParameters.ruleAction = "allow"
    | where %requestParameters.portRange.from = 0 and %requestParameters.portRange.to = 65535
    | count by eventname,%requestParameters.ruleAction,%requestParameters.portRange.from, %requestParameters.portRange.to, %"requestParameters.cidrBlock"

<img width="720" alt="image" src="https://github.com/gabizzle/Intrusion-Detection/assets/67624149/b2546e7b-7442-4eb0-85b2-fa0b061f07d3">

## References
- https://usa.kaspersky.com/resource-center/definitions/what-is-cloud-security
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html 
