---
title: AWS Classic resource usage.
shortcode: no-classic-resources
summary: AWS Classic resource usage. 
permalink: /docs/redshift/no-classic-resources/
---

### Explanation

AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

### Possible Impact
Classic resources are running in a shared environment with other customers

### Suggested Resolution
Switch to VPC resources


### Insecure Example

The following example will fail the AVD-AWS-0085 check.

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

The following example will pass the AVD-AWS-0085 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:


```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html)


