package workspaces

import (
	"fmt"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: getWorkSpaces(cfFile),
	}
}

func getWorkSpaces(ctx parser.FileContext) (workSpaces []workspaces.WorkSpace) {
	for _, resource := range ctx.GetResourceByType("AWS::WorkSpaces::Workspace") {
		var workspace workspaces.WorkSpace
		rootEncrypted := resource.GetProperty("RootVolumeEncryptionEnabled")
		if rootEncrypted.IsNil() || rootEncrypted.IsNotBool() {
			workspace.RootVolume.Encryption.Enabled = types.BoolDefault(false, resource.Metadata())
		} else {
			workspace.RootVolume.Encryption.Enabled = rootEncrypted.AsBoolValue()
		}
		userEncrypted := resource.GetProperty("UserVolumeEncryptionEnabled")
		if userEncrypted.IsNil() || userEncrypted.IsNotBool() {
			workspace.UserVolume.Encryption.Enabled = types.BoolDefault(false, resource.Metadata())
		} else {
			workspace.UserVolume.Encryption.Enabled = userEncrypted.AsBoolValue()
		}

		fmt.Printf("WORKSPACE: ROOT: %#v USER: %#v\n\n", workspace.RootVolume.Encryption.Enabled.Value(), workspace.UserVolume.Encryption.Enabled.Value())

		workSpaces = append(workSpaces, workspace)
	}
	return workSpaces
}
