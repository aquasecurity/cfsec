---
title: SAM Simple table must have server side encryption enabled.
shortcode: enable-table-encryption
summary: SAM Simple table must have server side encryption enabled. 
permalink: /docs/sam/enable-table-encryption/
---

### Explanation

Encryption should be enabled at all available levels to ensure that data is protected if compromised.

### Possible Impact
Data stored in the table that is unencrypted may be vulnerable to compromise

### Suggested Resolution
Enable server side encryption


### Insecure Example

The following example will fail the AVD-AWS-0121 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Table
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
      SSESpecification:
        SSEEnabled: false

```



### Secure Example

The following example will pass the AVD-AWS-0121 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Table
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification)


