# cfsec

[![GoReportCard](https://goreportcard.com/badge/github.com/aquasecurity/cfsec)](https://goreportcard.com/report/github.com/aquasecurity/cfsec)

> NOTE: cfsec is early release status - please raise issues and be patient

## What is it?

cfsec scans your yaml or json cloudformation configuration files for common security misconfigurations.

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


