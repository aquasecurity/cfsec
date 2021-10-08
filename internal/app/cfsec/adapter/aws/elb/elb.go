package elb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elb.ELB {

	return elb.ELB{
		LoadBalancers: getLoadBalancers(cfFile),
	}
}
