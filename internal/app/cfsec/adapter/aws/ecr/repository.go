package ecr

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/util"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
)

func getRepositories(ctx parser.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourceByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {
		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				ScanOnPush: r.GetBoolProperty("ImageScanningConfiguration.ScanOnPush"),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Policy:             getPolicyDocument(r),
			Encryption: ecr.Encryption{
				Type:     r.GetStringProperty("EncryptionConfiguration.EncryptionType", ecr.EncryptionTypeAES256),
				KMSKeyID: r.GetStringProperty("EncryptionConfiguration.KmsKey"),
			},
		}
		repositories = append(repositories, repository)
	}

	return repositories
}

func getPolicyDocument(r *parser.Resource) (policy iam.PolicyDocument) {
	policyProp := r.GetProperty("RepositoryPolicyText")
	if policyProp.IsNil() {
		return policy
	}

	policyDoc := util.GetJsonBytes(policyProp, r.SourceFormat())

	doc, _ := iam.ParsePolicyDocument(policyDoc, policyProp.Metadata())
	return *doc
}

func hasImmutableImageTags(r *parser.Resource) types.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() || !mutabilityProp.EqualTo("IMMUTABLE") {
		return types.BoolDefault(false, r.Metadata())
	}
	return types.Bool(true, mutabilityProp.Metadata())
}

