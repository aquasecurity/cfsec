---
title: IAM policy should avoid use of wildcards and instead apply the principle of least privilege
shortcode: no-policy-wildcards
summary: IAM policy should avoid use of wildcards and instead apply the principle of least privilege 
permalink: /docs/iam/no-policy-wildcards/
---

### Explanation

You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.

### Possible Impact
Overly permissive policies may grant access to sensitive resources

### Suggested Resolution
Specify the exact permissions required, and to which resources they should apply instead of using wildcards.


### Insecure Example

The following example will fail the AVD-AWS-0057 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of policy
Resources:
  BadPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 'cloudformation:Describe*'
              - 'cloudformation:List*'
              - 'cloudformation:Get*'
            Resource: '*'

```



### Secure Example

The following example will pass the AVD-AWS-0057 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of policy
Resources:
  GoodPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: CFNUsers
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - 's3:ListBuckets'
            Resource: 'specific-bucket'

```




### Related Links


- [https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)


