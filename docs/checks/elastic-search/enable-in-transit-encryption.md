---
title: Elasticsearch domain uses plaintext traffic for node to node communication.
shortcode: enable-in-transit-encryption
summary: Elasticsearch domain uses plaintext traffic for node to node communication. 
permalink: /docs/elastic-search/enable-in-transit-encryption/
---

### Explanation

Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.

### Possible Impact
In transit data between nodes could be read if intercepted

### Suggested Resolution
Enable encrypted node to node communication


### Insecure Example

The following example will fail the AVD-AWS-0043 check.

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

The following example will pass the AVD-AWS-0043 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: 'test'
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
      NodeToNodeEncryptionOptions:
        Enabled: true

```




### Related Links


- [https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html)


