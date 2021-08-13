# cfsec

## What might it be

tfsec is the premier terraform scanning tool. cfsec may be the solution for this. The concepts of blocks and attributes are already present in tfsec and should be reusable in cfsec

## An Example

Given the Cloud Formation configuration file below;

```yaml
Parameters:
  BucketName: 
    Type: String
    Default: naughty
  BucketKeyEnabled:
    Type: Boolean
    Default: false

Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: 
        Ref: BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: 
            Ref: BucketKeyEnabled

```

Running the command `cfsec example.yaml`

The output would be

![screenshot.png](screenshot.png)


