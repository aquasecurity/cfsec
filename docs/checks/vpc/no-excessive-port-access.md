---
title: An ingress Network ACL rule allows ALL ports.
shortcode: no-excessive-port-access
summary: An ingress Network ACL rule allows ALL ports. 
permalink: /docs/vpc/no-excessive-port-access/
---

### Explanation

Ensure access to specific required ports is allowed, and nothing else.

### Possible Impact
All ports exposed for egressing data

### Suggested Resolution
Set specific allowed ports


### Insecure Example

The following example will fail the AVD-AWS-0102 check.

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
      Protocol: -1

```



### Secure Example

The following example will pass the AVD-AWS-0102 check.

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

```




### Related Links


- [https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)


