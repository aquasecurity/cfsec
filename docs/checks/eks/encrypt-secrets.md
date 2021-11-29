---
title: EKS should have the encryption of secrets enabled
shortcode: encrypt-secrets
summary: EKS should have the encryption of secrets enabled 
permalink: /docs/eks/encrypt-secrets/
---

### Explanation

EKS cluster resources should have the encryption_config block set with protection of the secrets resource.

### Possible Impact
EKS secrets could be read if compromised

### Suggested Resolution
Enable encryption of EKS secrets


### Insecure Example

The following example will fail the AVD-AWS-0039 check.

```yaml
---
Resources:
  BadExample:
    Type: 'AWS::EKS::Cluster'
    Properties:
      Name: badExample
      Version: '1.14'
      RoleArn: >-
        arn:aws:iam::012345678910:role/eks-service-role-bad-example
      ResourcesVpcConfig:
        SecurityGroupIds:
          - sg-6979fe18
        SubnetIds:
          - subnet-6782e71e
          - subnet-e7e761ac

```



### Secure Example

The following example will pass the AVD-AWS-0039 check.

```yaml
---
Resources:
  GoodExample:
    Type: 'AWS::EKS::Cluster'
    Properties:
      Name: goodExample
      Version: '1.14'
      RoleArn: >-
        arn:aws:iam::012345678910:role/eks-service-role-good-example
      EncryptionConfig:
        Provider:
          KeyArn: alias/eks-kms
        Resources:
        - secrets
      ResourcesVpcConfig:
        SecurityGroupIds:
          - sg-6979fe18
        SubnetIds:
          - subnet-6782e71e
          - subnet-e7e761ac

```




### Related Links


- [https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/](https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/)


