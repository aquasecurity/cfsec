---
title: Elasticsearch doesn't enforce HTTPS traffic.
shortcode: enforce-https
summary: Elasticsearch doesn't enforce HTTPS traffic. 
permalink: /docs/elastic-search/enforce-https/
---

### Explanation

Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.

### Possible Impact
HTTP traffic can be intercepted and the contents read

### Suggested Resolution
Enforce the use of HTTPS for ElasticSearch


### Insecure Example

The following example will fail the AVD-AWS-0046 check.

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

The following example will pass the AVD-AWS-0046 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
      DomainEndpointOptions:
        EnforceHTTPS: true
        
      ElasticsearchVersion: '7.10'
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


