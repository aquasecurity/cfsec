package workspaces

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/workspaces"
)

func Adapt(cfFile parser.FileContext) workspaces.WorkSpaces {
	return workspaces.WorkSpaces{
		WorkSpaces: getWorkSpaces(cfFile),
	}
}
