package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/athena"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) athena.Athena {

	return athena.Athena{
		Workgroups: getWorkGroups(cfFile),
	}
}
