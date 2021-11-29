---
title: DAX Cluster should always encrypt data at rest
shortcode: enable-at-rest-encryption
summary: DAX Cluster should always encrypt data at rest 
permalink: /docs/dynamodb/enable-at-rest-encryption/
---

### Explanation

Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Enable encryption at rest for DAX Cluster


### Insecure Example

The following example will fail the AVD-AWS-0023 check.

```yaml
---
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster created with CloudFormation"
      SubnetGroupName: !Ref subnetGroupClu

```



### Secure Example

The following example will pass the AVD-AWS-0023 check.

```yaml
---
Resources:
  daxCluster:
    Type: AWS::DAX::Cluster
    Properties:
      ClusterName: "MyDAXCluster"
      NodeType: "dax.r3.large"
      ReplicationFactor: 1
      IAMRoleARN: "arn:aws:iam::111122223333:role/DaxAccess"
      Description: "DAX cluster created with CloudFormation"
      SSESpecification:
        SSEEnabled: true

```




### Related Links


- [https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html)

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html)


