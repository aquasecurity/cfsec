package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/s3"
)

func Adapt(cfFile parser.FileContext) s3.S3 {

	return s3.S3{
		Buckets: getBuckets(cfFile),
	}
}
