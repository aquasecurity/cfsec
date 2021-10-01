package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
)

func Adapt(cfFile parser.FileContext) elasticache.ElastiCache {
	return elasticache.ElastiCache{
		Clusters:          nil,
		ReplicationGroups: nil,
		SecurityGroups:    getSecurityGroups(cfFile),
	}
}
