package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) cloudfront.Cloudfront {

	return cloudfront.Cloudfront{
		Distributions: getDistributions(cfFile),
	}
}
