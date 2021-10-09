package cloudtrail

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudtrail.CloudTrail {

	return cloudtrail.CloudTrail{
		Trails: getCloudTrails(cfFile),
	}

}
