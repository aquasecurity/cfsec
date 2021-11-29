---
title: A MSK cluster allows unencrypted data in transit.
shortcode: enable-in-transit-encryption
summary: A MSK cluster allows unencrypted data in transit. 
permalink: /docs/msk/enable-in-transit-encryption/
---

### Explanation

Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.

### Possible Impact
Intercepted data can be read in transit

### Suggested Resolution
Enable in transit encryption


### Insecure Example

The following example will fail the AVD-AWS-0073 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS_PLAINTEXT"


```



### Secure Example

The following example will pass the AVD-AWS-0073 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      EncryptionInfo:
        EncryptionInTransit:
          ClientBroker: "TLS"

```




### Related Links


- [https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html](https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html)


