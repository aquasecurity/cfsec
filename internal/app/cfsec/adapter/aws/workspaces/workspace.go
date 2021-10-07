package workspaces

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
)

func getWorkSpaces(ctx parser.FileContext) (workSpaces []workspaces.WorkSpace) {
	for _, r := range ctx.GetResourceByType("AWS::WorkSpaces::Workspace") {
		workspace := workspaces.WorkSpace{
			RootVolume: workspaces.Volume{
				Encryption: workspaces.Encryption{
					Enabled: r.GetBoolProperty("RootVolumeEncryptionEnabled"),
				},
			},
			UserVolume: workspaces.Volume{
				Encryption: workspaces.Encryption{
					Enabled: r.GetBoolProperty("UserVolumeEncryptionEnabled"),
				},
			},
		}

		workSpaces = append(workSpaces, workspace)
	}
	return workSpaces
}
