package ebs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ebs"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ebs.EBS {
	return ebs.EBS{
		Volumes: getVolumes(cfFile),
	}

}
