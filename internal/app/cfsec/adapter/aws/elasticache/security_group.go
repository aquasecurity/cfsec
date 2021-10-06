package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/types"
)

func getSecurityGroups(ctx parser.FileContext) (securityGroups []elasticache.SecurityGroup) {

	sgResources := ctx.GetResourceByType("AWS::ElastiCache::SecurityGroup")

	for _, r := range sgResources {

		sg := elasticache.SecurityGroup{
			Metadata:    r.Metadata(),
			Description: getDescription(r),
		}
		securityGroups = append(securityGroups, sg)
	}

	return securityGroups
}

func getDescription(r *parser.Resource) types.StringValue {

	descProp := r.GetProperty("Description")
	if descProp.IsNotString() {
		return types.StringDefault("", r.Metadata())
	}
	return descProp.AsStringValue()
}
