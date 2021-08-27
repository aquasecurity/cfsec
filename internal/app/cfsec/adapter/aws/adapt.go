package aws

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter/aws/s3"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws"
)

func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		S3: s3.Adapt(cfFile),
	}
}
