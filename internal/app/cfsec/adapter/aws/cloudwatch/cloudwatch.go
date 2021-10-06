package cloudwatch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
)

func Adapt(cfFile parser.FileContext) cloudwatch.CloudWatch {

	return cloudwatch.CloudWatch{
		LogGroups: getLogGroups(cfFile),
	}
}
