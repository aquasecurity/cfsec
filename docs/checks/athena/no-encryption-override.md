---
title: Athena workgroups should enforce configuration to prevent client disabling encryption
shortcode: no-encryption-override
summary: Athena workgroups should enforce configuration to prevent client disabling encryption 
permalink: /docs/athena/no-encryption-override/
---

### Explanation

Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.

### Possible Impact
Clients can ignore encryption requirements

### Suggested Resolution
Enforce the configuration to prevent client overrides


### Insecure Example

The following example will fail the AVD-AWS-0007 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: false
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup

```



### Secure Example

The following example will pass the AVD-AWS-0007 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup

```




### Related Links


- [https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html](https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html)


