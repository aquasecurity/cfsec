---
title: A database resource is marked as publicly accessible.
shortcode: no-public-db-access
summary: A database resource is marked as publicly accessible. 
permalink: /docs/rds/no-public-db-access/
---

### Explanation

Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.

### Possible Impact
The database instance is publicly accessible

### Suggested Resolution
Set the database to not be publicly accessible


### Insecure Example

The following example will fail the AVD-AWS-0082 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true


```



### Secure Example

The following example will pass the AVD-AWS-0082 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false


```




### Related Links


- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding)


