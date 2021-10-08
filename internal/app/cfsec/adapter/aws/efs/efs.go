package efs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/efs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) efs.EFS {

	return efs.EFS{
		FileSystems: getFileSystems(cfFile),
	}
}
