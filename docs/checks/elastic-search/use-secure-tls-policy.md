---
title: Elasticsearch domain endpoint is using outdated TLS policy.
shortcode: use-secure-tls-policy
summary: Elasticsearch domain endpoint is using outdated TLS policy. 
permalink: /docs/elastic-search/use-secure-tls-policy/
---

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the AVD-AWS-0047 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      ElasticsearchVersion: '7.10'
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: '2'
        ZoneAwarenessEnabled: true
        InstanceType: 'm3.medium.elasticsearch'
        DedicatedMasterType: 'm3.medium.elasticsearch'
        DedicatedMasterCount: '3'
      EBSOptions:
        EBSEnabled: true
        Iops: '0'
        VolumeSize: '20'
        VolumeType: 'gp2'

```



### Secure Example

The following example will pass the AVD-AWS-0047 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      ElasticsearchVersion: '7.10'
      DomainEndpointOptions:
        TLSSecurityPolicy: Policy-Min-TLS-1-2-2019-07
      EncryptionAtRestOptions:
        Enabled: true
        KmsKeyId: alias/kmskey
      ElasticsearchClusterConfig:
        DedicatedMasterEnabled: true
        InstanceCount: '2'
        ZoneAwarenessEnabled: true
        InstanceType: 'm3.medium.elasticsearch'
        DedicatedMasterType: 'm3.medium.elasticsearch'
        DedicatedMasterCount: '3'
      EBSOptions:
        EBSEnabled: true
        Iops: '0'
        VolumeSize: '20'
        VolumeType: 'gp2'

```




### Related Links


- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html)


