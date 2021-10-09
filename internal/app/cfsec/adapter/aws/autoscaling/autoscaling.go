package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) autoscaling.Autoscaling {

	return autoscaling.Autoscaling{
		LaunchConfigurations: getLaunchConfigurations(cfFile),
	}
}
