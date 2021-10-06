package ebs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ebs"
	"github.com/aquasecurity/defsec/types"
)

func getVolumes(ctx parser.FileContext) (volumes []ebs.Volume) {

	volumeResources := ctx.GetResourceByType("AWS::EC2::Volume")
	for _, r := range volumeResources {

		volume := ebs.Volume{
			Metadata: r.Metadata(),
			Encryption: ebs.Encryption{
				Enabled:  isEncryptionEnabled(r),
				KMSKeyID: getKmsKeyId(r),
			},
		}

		volumes = append(volumes, volume)
	}
	return volumes
}

func getKmsKeyId(r *parser.Resource) types.StringValue {
	kmsIdProp := r.GetProperty("KmsKeyId")
	if kmsIdProp.IsNil() || kmsIdProp.IsNotString() {
		return types.StringDefault("", r.Metadata())
	}
	return kmsIdProp.AsStringValue()
}

func isEncryptionEnabled(r *parser.Resource) types.BoolValue {
	encryptedProp := r.GetProperty("Encrypted")
	if encryptedProp.IsNil() || encryptedProp.IsNotBool() {
		return types.BoolDefault(false, r.Metadata())
	}
	return encryptedProp.AsBoolValue()
}
