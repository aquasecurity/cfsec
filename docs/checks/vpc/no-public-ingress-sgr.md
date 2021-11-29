---
title: An ingress security group rule allows traffic from /0.
shortcode: no-public-ingress-sgr
summary: An ingress security group rule allows traffic from /0. 
permalink: /docs/vpc/no-public-ingress-sgr/
---

### Explanation

Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
Your port exposed to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the AVD-AWS-0107 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of ingress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 80.1.2.3/32
        IpProtocol: "6"

```



### Secure Example

The following example will pass the AVD-AWS-0107 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupIngress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"

```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html)


