package ecr

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/ecr"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ecr.ECR {

	return ecr.ECR{
		Repositories: getRepositories(cfFile),
	}
}
