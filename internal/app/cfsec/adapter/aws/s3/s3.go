package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/s3"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) s3.S3 {

	buckets := getBuckets(cfFile)

	return s3.S3{
		Buckets:            buckets,
		PublicAccessBlocks: getPublicAccessBlocks(buckets),
	}
}

func getPublicAccessBlocks(buckets []s3.Bucket) (publicAccessBlocks []s3.PublicAccessBlock) {
	for _, b := range buckets {
		if b.PublicAccessBlock != nil {
			publicAccessBlocks = append(publicAccessBlocks, *b.PublicAccessBlock)
		}
	}
	return publicAccessBlocks
}
