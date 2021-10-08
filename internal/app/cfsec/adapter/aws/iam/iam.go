package iam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/iam"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) iam.IAM {
	return iam.IAM{
		Policies:      getPolicies(cfFile),
		RolePolicies:  getRolePolicies(cfFile),
		UserPolicies:  getUserPolicies(cfFile),
		GroupPolicies: getGroupPolicies(cfFile),
	}
}
