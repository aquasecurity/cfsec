package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/vpc"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) vpc.VPC {
	return vpc.VPC{
		DefaultVPCs:    getDefaultVPCs(),
		SecurityGroups: getSecurityGroups(cfFile),
		NetworkACLs:    getNetworkACLs(cfFile),
	}
}

func getDefaultVPCs() []vpc.DefaultVPC {
	// NOTE: it appears you can no longer create default VPCs via CF
	return nil
}
