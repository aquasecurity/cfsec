package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/rds"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) rds.RDS {
	clusters, orphans := getClustersAndInstances(cfFile)

	return rds.RDS{
		Instances: orphans,
		Clusters:  clusters,
		Classic:   getClassic(cfFile),
	}
}
