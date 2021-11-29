---
title: Redshift clusters should use at rest encryption
shortcode: encryption-customer-key
summary: Redshift clusters should use at rest encryption 
permalink: /docs/redshift/encryption-customer-key/
---

### Explanation

Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.

### Possible Impact
Data may be leaked if infrastructure is compromised

### Suggested Resolution
Enable encryption using CMK


### Insecure Example

The following example will fail the AVD-AWS-0084 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true

```



### Secure Example

The following example will pass the AVD-AWS-0084 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of redshift cluster
Resources:
  Queue:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      KmsKeyId: "something"


```




### Related Links


- [https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html)


