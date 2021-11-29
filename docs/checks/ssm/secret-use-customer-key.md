---
title: Secrets Manager should use customer managed keys
shortcode: secret-use-customer-key
summary: Secrets Manager should use customer managed keys 
permalink: /docs/ssm/secret-use-customer-key/
---

### Explanation

Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.

### Possible Impact
Using AWS managed keys reduces the flexibility and control over the encryption key

### Suggested Resolution
Use customer managed keys


### Insecure Example

The following example will fail the AVD-AWS-0098 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of secret
Resources:
  BadSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      Name: "blah"
      SecretString: "don't tell anyone"

```



### Secure Example

The following example will pass the AVD-AWS-0098 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of ingress rule
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"

```




### Related Links


- [https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt](https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt)


