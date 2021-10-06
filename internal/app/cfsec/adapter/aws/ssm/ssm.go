package ssm

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) ssm.SSM {
	return ssm.SSM{
		Secrets: getSecrets(cfFile),
	}
}

func getSecrets(ctx parser.FileContext) (secrets []ssm.Secret) {
	for _, secretResource := range ctx.GetResourceByType("AWS::SecretsManager::Secret") {
		var secret ssm.Secret
		secret.Metadata = secretResource.Metadata()
		if prop := secretResource.GetProperty("KmsKeyId"); prop.IsString() {
			secret.KMSKeyID = prop.AsStringValue()
		} else {
			secret.KMSKeyID = types.StringDefault("", secretResource.Metadata())
		}
		secrets = append(secrets, secret)
	}
	return secrets
}
