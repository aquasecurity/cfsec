---
title: An egress security group rule allows traffic to /0.
shortcode: no-public-egress-sgr
summary: An egress security group rule allows traffic to /0. 
permalink: /docs/vpc/no-public-egress-sgr/
---

### Explanation

Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.

### Possible Impact
Your port is egressing data to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the AVD-AWS-0104 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 80.1.2.3/32
        IpProtocol: "6"

```



### Secure Example

The following example will pass the AVD-AWS-0104 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"

```




### Related Links


- [https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html)


