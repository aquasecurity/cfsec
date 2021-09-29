package aws

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/apigateway"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/athena"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/autoscaling"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudfront"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudtrail"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/cloudwatch"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/codebuild"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/config"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/documentdb"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/dynamodb"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/ebs"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/s3"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/vpc"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/workspaces"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws"
)

func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		APIGateway:  apigateway.Adapt(cfFile),
		Athena:      athena.Adapt(cfFile),
		Autoscaling: autoscaling.Adapt(cfFile),
		Cloudfront:  cloudfront.Adapt(cfFile),
		CloudTrail:  cloudtrail.Adapt(cfFile),
		CloudWatch:  cloudwatch.Adapt(cfFile),
		CodeBuild:   codebuild.Adapt(cfFile),
		Config:      config.Adapt(cfFile),
		DocumentDB:  documentdb.Adapt(cfFile),
		DynamoDB:    dynamodb.Adapt(cfFile),
		EBS:         ebs.Adapt(cfFile),
		S3:          s3.Adapt(cfFile),
		VPC:         vpc.Adapt(cfFile),
		WorkSpaces:  workspaces.Adapt(cfFile),
	}
}
