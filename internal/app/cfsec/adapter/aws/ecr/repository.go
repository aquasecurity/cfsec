package ecr

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/util"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
	"gopkg.in/yaml.v2"
)

func getRepositories(ctx parser.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourceByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {
		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				ScanOnPush: shouldScanOnPush(r),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Policy:             getPolicyDocument(r),
			Encryption: ecr.Encryption{
				Type:     getEncryptionType(r),
				KMSKeyID: getKmsKeyId(r),
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
	policy = *doc
	return policy
}

func getEncryptionType(r *parser.Resource) types.StringValue {
	encTypeProp := r.GetProperty("EncryptionConfiguration.EncryptionType")
	if encTypeProp.IsNil() || encTypeProp.IsNotString() {
		return types.StringDefault(ecr.EncryptionTypeAES256, r.Metadata())
	}
	return encTypeProp.AsStringValue()
}

func getKmsKeyId(r *parser.Resource) types.StringValue {
	keyProp := r.GetProperty("EncryptionConfiguration.KmsKey")
	if keyProp.IsNil() || keyProp.IsNotString() {
		return types.StringDefault("", r.Metadata())
	}
	return keyProp.AsStringValue()
}

func hasImmutableImageTags(r *parser.Resource) types.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() || !mutabilityProp.EqualTo("IMMUTABLE") {
		return types.BoolDefault(false, r.Metadata())
	}
	return types.Bool(true, mutabilityProp.Metadata())
}

func shouldScanOnPush(r *parser.Resource) types.BoolValue {
	pushScanProp := r.GetProperty("ImageScanningConfiguration.ScanOnPush")
	if pushScanProp.IsNil() || pushScanProp.IsNotBool() {
		return types.BoolDefault(false, r.Metadata())
	}
	return pushScanProp.AsBoolValue()
}

func recreatePolicyDocument(policyProp *parser.Property, format parser.SourceFormat) []byte {
	lines, err := policyProp.AsRawStrings()
	if err != nil {
		return nil
	}
	if format == parser.JsonSourceFormat {
		return []byte(strings.Join(lines, " "))
	}

	lines = removeLeftMargin(lines)

	yamlContent := strings.Join(lines, "\n")
	var body interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &body); err != nil {
		return nil
	}
	jsonBody := convert(body)
	policyJson, err := json.MarshalIndent(jsonBody, "", "  ")
	if err != nil {
		return nil
	}
	return policyJson

}

func removeLeftMargin(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	prefixSpace := len(lines[0]) - len(strings.TrimLeft(lines[0], " "))

	for i, line := range lines {
		lines[i] = line[prefixSpace:]
	}
	return lines
}

func convert(input interface{}) interface{} {
	switch x := input.(type) {
	case map[interface{}]interface{}:
		outpMap := map[string]interface{}{}
		for k, v := range x {
			outpMap[k.(string)] = convert(v)
		}
		return outpMap
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return input
}
