---
title: CodeBuild Project artifacts encryption should not be disabled
shortcode: enable-encryption
summary: CodeBuild Project artifacts encryption should not be disabled 
permalink: /docs/codebuild/enable-encryption/
---

### Explanation

All artifacts produced by your CodeBuild project pipeline should always be encrypted

### Possible Impact
CodeBuild project artifacts are unencrypted

### Suggested Resolution
Enable encryption for CodeBuild project artifacts


### Insecure Example

The following example will fail the AVD-AWS-0018 check.

```yaml
---
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: true
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: false
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"

```



### Secure Example

The following example will pass the AVD-AWS-0018 check.

```yaml
---
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        ArtifactIdentifier: "String"
        EncryptionDisabled: false
        Location: "String"
        Name: "String"
        NamespaceType: "String"
        OverrideArtifactName: false
        Packaging: "String"
        Path: "String"
        Type: "String"
      SecondaryArtifacts:
        - ArtifactIdentifier: "String"
          EncryptionDisabled: false
          Location: "String"
          Name: "String"
          NamespaceType: "String"
          OverrideArtifactName: false
          Packaging: "String"
          Path: "String"
          Type: "String"

```




### Related Links


- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html)

- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html)


