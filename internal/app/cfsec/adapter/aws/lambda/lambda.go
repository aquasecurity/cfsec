package lambda

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/lambda"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) lambda.Lambda {

	return lambda.Lambda{
		Functions: getFunctions(cfFile),
	}
}
