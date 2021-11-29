---
title: Missing description for security group/security group rule.
shortcode: add-description-to-security-group
summary: Missing description for security group/security group rule. 
permalink: /docs/redshift/add-description-to-security-group/
---

### Explanation

Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups and rules


### Insecure Example

The following example will fail the AVD-AWS-0083 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift sgr
Resources:
  Queue:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: ""


```



### Secure Example

The following example will pass the AVD-AWS-0083 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:
  Queue:
    Type: AWS::Redshift::ClusterSecurityGroup
    Properties:
      Description: "Disallow bad stuff"


```




### Related Links


- [https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html](https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html)


