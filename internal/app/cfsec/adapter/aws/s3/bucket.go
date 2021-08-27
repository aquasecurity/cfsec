package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/types"
)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket

	bucketResources := cfFile.GetResourceByType("AWS::S3::Bucket")

	for _, r := range bucketResources {

		s3b := s3.Bucket{
			Name:       getName(r, cfFile),
			Encryption: getEncryption(r, cfFile),
			Metadata:   r.Metadata(),
		}

		buckets = append(buckets, s3b)
	}
	return buckets
}

func getName(r *parser.Resource, ctx parser.FileContext) types.StringValue {
	p := r.GetProperty("BucketName")

	if p.IsNil() {
		return types.StringDefault("", r.Metadata())
	}

	// add code for reference lookup

	return types.String(p.AsString(), r.Metadata())
}

func getEncryption(r *parser.Resource, ctx parser.FileContext) s3.Encryption {

	encryptProps := r.GetPropertyForPath("BucketEncryption.ServerSideEncryptionConfiguration")

	if encryptProps.IsNil() {
		return s3.Encryption{
			Enabled:   types.BoolDefault(false, r.Metadata()),
			Algorithm: types.StringDefault("", r.Metadata()),
			KMSKeyId:  types.StringDefault("", r.Metadata()),
		}
	}

	first := encryptProps.AsList()[0]

	setValue := first.GetProperty("BucketKeyEnabled").ResolveValue(ctx)

	return s3.Encryption{
		Enabled:   types.Bool(setValue.AsBool(), first.MetadataWithValue(setValue)),
		Algorithm: types.StringDefault("", r.Metadata()),
		KMSKeyId:  types.StringDefault("", r.Metadata()),
	}

}
