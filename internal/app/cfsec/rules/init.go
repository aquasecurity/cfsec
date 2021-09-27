package rules

import (
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/apigateway"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/athena"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/autoscaling"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/cloudfront"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/cloudtrail"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/cloudwatch"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/config"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/documentdb"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/ebs"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/ec2"
		_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules/aws/s3"
)
