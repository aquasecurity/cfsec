---
title: Redshift cluster should be deployed into a specific VPC
shortcode: use-vpc
summary: Redshift cluster should be deployed into a specific VPC 
permalink: /docs/redshift/use-vpc/
---

### Explanation

Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tennant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.

### Possible Impact
Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode

### Suggested Resolution
Deploy Redshift cluster into a non default VPC


### Insecure Example

The following example will fail the AVD-AWS-0085 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: ""


```



### Secure Example

The following example will pass the AVD-AWS-0085 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterSubnetGroupName: "my-subnet-group"


```




### Related Links


- [https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html](https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html)


