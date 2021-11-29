---
title: AWS Classic resource usage.
shortcode: no-classic-resources
summary: AWS Classic resource usage. 
permalink: /docs/rds/no-classic-resources/
---

### Explanation

AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.

### Possible Impact
Classic resources are running in a shared environment with other customers

### Suggested Resolution
Switch to VPC resources


### Insecure Example

The following example will fail the AVD-AWS-0081 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Queue:
    Type: AWS::RDS::DBSecurityGroup
    Properties:
      Description: ""


```



### Secure Example

The following example will pass the AVD-AWS-0081 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:


```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html)


