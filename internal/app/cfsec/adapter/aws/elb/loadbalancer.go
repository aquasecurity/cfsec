package elb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elb"
	"github.com/aquasecurity/defsec/types"
)

func getLoadBalancers(ctx parser.FileContext) (loadbalancers []elb.LoadBalancer) {

	loadBalanacerResources := ctx.GetResourceByType("AWS::ElasticLoadBalancingV2::LoadBalancer")

	for _, r := range loadBalanacerResources {
		lb := elb.LoadBalancer{
			Metadata:                r.Metadata(),
			Type:                    r.GetStringProperty("Type", "application"),
			DropInvalidHeaderFields: checkForDropInvalidHeaders(r),
			Internal:                isInternal(r),
			Listeners:               getListeners(r, ctx),
		}
		loadbalancers = append(loadbalancers, lb)
	}

	return loadbalancers
}

func getListeners(lbr *parser.Resource, ctx parser.FileContext) (listeners []elb.Listener) {

	listenerResources := ctx.GetResourceByType("AWS::ElasticLoadBalancingV2::Listener")

	for _, r := range listenerResources {
		if r.GetStringProperty("LoadBalancerArn").Value() == lbr.ID() {
			listener := elb.Listener{
				Metadata:      r.Metadata(),
				Protocol:      r.GetStringProperty("Protocol", "HTTP"),
				TLSPolicy:     r.GetStringProperty("SslPolicy", "ELBSecurityPolicy-2016-08"),
				DefaultAction: getDefaultListenerAction(r),
			}

			listeners = append(listeners, listener)
		}
	}
	return listeners
}

func getDefaultListenerAction(r *parser.Resource) (action elb.Action) {
	defaultActionsProp := r.GetProperty("DefaultActions")
	if defaultActionsProp.IsNotList() || len(defaultActionsProp.AsList()) == 0 {
		return action
	}
	action.Type = defaultActionsProp.AsList()[0].GetProperty("Type").AsStringValue()
	return action
}

func isInternal(r *parser.Resource) types.BoolValue {
	schemeProp := r.GetProperty("Scheme")
	if schemeProp.IsNotString() {
		return r.BoolDefault(false)
	}
	return types.Bool(schemeProp.EqualTo("internal", parser.IgnoreCase), schemeProp.Metadata())
}

func checkForDropInvalidHeaders(r *parser.Resource) types.BoolValue {
	attributesProp := r.GetProperty("LoadBalancerAttributes")
	if attributesProp.IsNotList() {
		return types.BoolDefault(false, r.Metadata())
	}

	for _, attr := range attributesProp.AsList() {
		if attr.IsNotMap() {
			continue
		}
		for k, v := range attr.AsMap() {
			if k == "Key" && v.AsString() != "routing.http.drop_invalid_header_fields.enabled" {
				continue
			} else if v.IsBool() {
				return v.AsBoolValue()
			}
		}
	}

	return r.BoolDefault(false)
}
