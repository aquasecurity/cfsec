---
title: Missing description for security group/security group rule.
shortcode: add-description-for-security-group
summary: Missing description for security group/security group rule. 
permalink: /docs/elasticache/add-description-for-security-group/
---

### Explanation

Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.

### Possible Impact
Descriptions provide context for the firewall rule reasons

### Suggested Resolution
Add descriptions for all security groups and rules


### Insecure Example

The following example will fail the AVD-AWS-0049 check.

```yaml
---
Resources:
  BadExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Tags:
      - Name: BadExample
  BadExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: BadExample
      GroupDescription: Bad Elasticache Security Group
  BadSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: BadExampleCacheGroup
      EC2SecurityGroupName: BadExampleEc2SecurityGroup

```



### Secure Example

The following example will pass the AVD-AWS-0049 check.

```yaml
---
Resources:
  GoodExampleCacheGroup:
    Type: AWS::ElastiCache::SecurityGroup
    Properties:
      Description: Some description
  GoodExampleEc2SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: GoodExample
      GroupDescription: Good Elasticache Security Group
  GoodSecurityGroupIngress:
    Type: AWS::ElastiCache::SecurityGroupIngress
    Properties: 
      CacheSecurityGroupName: GoodExampleCacheGroup
      EC2SecurityGroupName: GoodExampleEc2SecurityGroup

```




### Related Links


- [https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html)


