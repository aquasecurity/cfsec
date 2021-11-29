---
title: Missing description for security group rule.
shortcode: add-description-to-security-group-rule
summary: Missing description for security group rule. 
permalink: /docs/vpc/add-description-to-security-group-rule/
---

### Explanation

Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups rules


### Insecure Example

The following example will fail the AVD-AWS-0099 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of SGR description
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "-1"

```



### Secure Example

The following example will pass the AVD-AWS-0099 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of SGR description
Resources:
  GoodSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        Description: "Can connect to loopback"
        IpProtocol: "-1"

```




### Related Links


- [https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html](https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html)


