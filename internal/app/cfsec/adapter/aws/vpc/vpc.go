package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) vpc.VPC {
	return vpc.VPC{
		DefaultVPCs:    getDefaultVPCs(cfFile),
		SecurityGroups: getSecurityGroups(cfFile),
		NetworkACLs:    getNetworkACLs(cfFile),
	}
}

func getDefaultVPCs(ctx parser.FileContext) []vpc.DefaultVPC {
	// NOTE: it appears you can no longer create default VPCs via CF
	return nil
}

func getSecurityGroups(ctx parser.FileContext) (groups []vpc.SecurityGroup) {
	for _, groupResource := range ctx.GetResourceByType("AWS::EC2::SecurityGroup") {
		var group vpc.SecurityGroup
		group.Metadata = groupResource.Metadata()
		description := groupResource.GetProperty("GroupDescription")
		if description.IsNil() || description.IsNotString() {
			group.Description = types.StringDefault("", groupResource.Metadata())
		} else {
			group.Description = types.StringExplicit(description.AsString(), description.Metadata())
		}
		for _, egress := range groupResource.GetProperty("SecurityGroupEgress").AsList() {
			var rule vpc.SecurityGroupRule
			description := egress.GetProperty("Description")
			if description.IsNil() || description.IsNotString() {
				rule.Description = types.StringDefault("", groupResource.Metadata())
			} else {
				rule.Description = types.StringExplicit(description.AsString(), description.Metadata())
			}
			v4Cidr := egress.GetProperty("CidrIp")
			if v4Cidr.IsString() && v4Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v4Cidr.AsString(), v4Cidr.Metadata()))
			}
			v6Cidr := egress.GetProperty("CidrIpv6")
			if v6Cidr.IsString() && v6Cidr.AsStringValue().IsNotEmpty() {
				rule.CIDRs = append(rule.CIDRs, types.StringExplicit(v6Cidr.AsString(), v6Cidr.Metadata()))
			}
			group.EgressRules = append(group.EgressRules, rule)
		}
		groups = append(groups, group)
	}
	return groups
}

func getNetworkACLs(ctx parser.FileContext) (acls []vpc.NetworkACL) {
	for _, aclResource := range ctx.GetResourceByType("AWS::EC2::NetworkAcl") {
		var acl vpc.NetworkACL
		acl.Metadata = aclResource.Metadata()
		acl.Rules = getRules(aclResource.ID(), ctx)
		acls = append(acls, acl)
	}
	return acls
}

func getRules(id string, ctx parser.FileContext) (rules []vpc.NetworkACLRule) {
	for _, ruleResource := range ctx.GetResourceByType("AWS::EC2::NetworkAclEntry") {
		aclID := ruleResource.GetProperty("NetworkAclId")
		if aclID.IsString() && aclID.AsString() == id {
			var rule vpc.NetworkACLRule
			rule.Metadata = ruleResource.Metadata()
			if egressProperty := ruleResource.GetProperty("Egress"); egressProperty.IsBool() {
				if egressProperty.AsBool() {
					rule.Type = types.String(vpc.TypeEgress, egressProperty.Metadata())
				} else {
					rule.Type = types.String(vpc.TypeIngress, egressProperty.Metadata())
				}
			} else {
				rule.Type = types.StringDefault(vpc.TypeIngress, ruleResource.Metadata())
			}
			if actionProperty := ruleResource.GetProperty("RuleAction"); actionProperty.IsString() {
				if actionProperty.AsString() == vpc.ActionAllow {
					rule.Action = types.String(vpc.ActionAllow, actionProperty.Metadata())
				} else {
					rule.Action = types.String(vpc.ActionDeny, actionProperty.Metadata())
				}
			} else {
				rule.Action = types.StringDefault(vpc.ActionDeny, ruleResource.Metadata())
			}
			protocolProperty := ruleResource.GetProperty("Protocol")
			if protocolProperty.IsInt() {
				rule.Protocol = protocolProperty.AsIntValue()
			} else {
				rule.Protocol = types.IntDefault(-1, ruleResource.Metadata())
			}
			rules = append(rules, rule)
		}
	}
	return rules
}
