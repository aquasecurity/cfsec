package efs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/defsec/types"
)

func getFileSystems(ctx parser.FileContext) (filesystems []efs.FileSystem) {

	filesystemResources := ctx.GetResourceByType("AWS::EFS::FileSystem")

	for _, r := range filesystemResources {

		filesystem := efs.FileSystem{
			Metadata:  r.Metadata(),
			Encrypted: hasEncryptionEnabled(r),
		}

		filesystems = append(filesystems, filesystem)
	}

	return filesystems
}

func hasEncryptionEnabled(r *parser.Resource) types.BoolValue {

	encryptionProp := r.GetProperty("Encrypted")
	if encryptionProp.IsNil() || encryptionProp.IsNotBool() {
		return types.BoolDefault(false, r.Metadata())
	}
	return encryptionProp.AsBoolValue()
}
