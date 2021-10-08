package eks

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/eks"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) eks.EKS {

	return eks.EKS{
		Clusters: getClusters(cfFile),
	}

}
