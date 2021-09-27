package s3

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/types"
)

var aclConvertRegex = regexp.MustCompile(`[A-Z][^A-Z]*`)

func getBuckets(cfFile parser.FileContext) []s3.Bucket {
	var buckets []s3.Bucket
	bucketResources := cfFile.GetResourceByType("AWS::S3::Bucket")

	for _, r := range bucketResources {

		s3b := s3.Bucket{
			Name:       getName(r),
			Encryption: getEncryption(r, cfFile),
			Metadata:   r.Metadata(),
			ACL:        getAcl(r),
			Logging: s3.Logging{
				Enabled: hasLogging(r),
			},
			Versioning: s3.Versioning{
				Enabled: hasVersioning(r),
			},
			PublicAccessBlock: &s3.PublicAccessBlock{
				BlockPublicACLs:       getPublicBlockAccessValue(r, "BlockPublicAcls"),
				BlockPublicPolicy:     getPublicBlockAccessValue(r, "BlockPublicPolicy"),
				IgnorePublicACLs:      getPublicBlockAccessValue(r, "IgnorePublicACLs"),
				RestrictPublicBuckets: getPublicBlockAccessValue(r, "RestrictPublicBuckets"),
			},
		}

		buckets = append(buckets, s3b)
	}
	return buckets
}

func getName(r *parser.Resource) types.StringValue {
	bucketNameProp := r.GetProperty("BucketName")

	if bucketNameProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}

	// add code for reference lookup

	return types.String(bucketNameProp.AsString(), r.Metadata())
}

func getAcl(r *parser.Resource) types.StringValue {
	accessControlProp := r.GetProperty("AccessControl")

	if accessControlProp.IsNil() {
		return types.StringDefault("private", r.Metadata())
	}

	aclValue := convertAclValue(accessControlProp.AsString())
	return types.String(aclValue, accessControlProp.Metadata())
}

func convertAclValue(aclValue string) string {
	matches := aclConvertRegex.FindAllString(aclValue, -1)

	return strings.ToLower(strings.Join(matches, "-"))
}

func hasLogging(r *parser.Resource) types.BoolValue {

	loggingProps := r.GetProperty("LoggingConfiguration.DestinationBucketName")

	if loggingProps.IsNil() || loggingProps.IsEmpty() {

		return types.BoolDefault(false, r.Metadata())
	}

	return types.Bool(true, loggingProps.Metadata())
}

func hasVersioning(r *parser.Resource) types.BoolValue {
	versioningProp := r.GetProperty("VersioningConfiguration.Status")

	if versioningProp.IsNil() {
		return types.BoolDefault(false, r.Metadata())
	}

	versioningEnabled := false
	if versioningProp.EqualTo("Enabled") {
		versioningEnabled = true

	}
	return types.Bool(versioningEnabled, versioningProp.Metadata())
}

func getPublicBlockAccessValue(r *parser.Resource, propertyName string) types.BoolValue {

	prop := r.GetProperty(propertyName)

	if prop.IsNil() {
		return types.BoolDefault(false, r.Metadata())
	}
	return types.Bool(prop.IsTrue(), prop.Metadata())
}

func getEncryption(r *parser.Resource, ctx parser.FileContext) s3.Encryption {

	encryptProps := r.GetProperty("BucketEncryption.ServerSideEncryptionConfiguration")

	if encryptProps.IsNil() {
		return s3.Encryption{
			Enabled:   types.BoolDefault(false, r.Metadata()),
			Algorithm: types.StringDefault("", r.Metadata()),
			KMSKeyId:  types.StringDefault("", r.Metadata()),
		}
	}

	first := encryptProps.AsList()[0]
	bucketKeyEnabled := first.GetProperty("BucketKeyEnabled")

	return s3.Encryption{
		Enabled:   types.Bool(bucketKeyEnabled.AsBool(), first.MetadataWithValue(bucketKeyEnabled)),
		Algorithm: types.StringDefault("", r.Metadata()),
		KMSKeyId:  types.StringDefault("", r.Metadata()),
	}

}
