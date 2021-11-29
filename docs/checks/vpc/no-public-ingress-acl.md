---
title: An ingress Network ACL rule allows specific ports from /0.
shortcode: no-public-ingress-acl
summary: An ingress Network ACL rule allows specific ports from /0. 
permalink: /docs/vpc/no-public-ingress-acl/
---

### Explanation

Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.

### Possible Impact
The ports are exposed for ingressing data to the internet

### Suggested Resolution
Set a more restrictive cidr range


### Insecure Example

The following example will fail the AVD-AWS-0105 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of excessive ports
Resources:
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: "something"
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId:
        Ref: NetworkACL
      Protocol: 6
      CidrBlock: 0.0.0.0/0
      RuleAction: allow

```



### Secure Example

The following example will pass the AVD-AWS-0105 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Godd example of excessive ports
Resources: 
  NetworkACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: "something"
  Rule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId:
        Ref: NetworkACL
      Protocol: 6
      CidrBlock: 10.0.0.0/8
      RuleAction: allow

```




### Related Links


- [https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)


