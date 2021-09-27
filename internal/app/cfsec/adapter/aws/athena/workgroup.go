package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/defsec/types"
)

func getWorkGroups(cfFile parser.FileContext) []athena.Workgroup {

	var workgroups []athena.Workgroup

	workgroupResources := cfFile.GetResourceByType("AWS::Athena::WorkGroup")

	for _, r := range workgroupResources {

		wg := athena.Workgroup{
			Metadata: r.Metadata(),
			Name:     getName(r),
			Encryption: athena.EncryptionConfiguration{
				Type: getEncryptionType(r),
			},
			EnforceConfiguration: getConfigurationEnforcement(r),
		}

		workgroups = append(workgroups, wg)
	}

	return workgroups
}

func getName(r *parser.Resource) types.StringValue {

	nameProp := r.GetProperty("Name")

	if nameProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}

	return nameProp.AsStringValue()
}

func getEncryptionType(r *parser.Resource) types.StringValue {

	typeProp := r.GetProperty("WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.EncryptionOption")

	if typeProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}

	if typeProp.IsEmpty() {
		return types.StringDefault("", typeProp.Metadata())
	}

	return typeProp.AsStringValue()
}

func getConfigurationEnforcement(r *parser.Resource) types.BoolValue {

	enforceProp := r.GetProperty("WorkGroupConfiguration.EnforceWorkGroupConfiguration")

	if enforceProp.IsNil() {
		return types.BoolDefault(false, r.Metadata())
	}

	if !enforceProp.IsBool() {
		return types.BoolDefault(false, enforceProp.Metadata())
	}

	return enforceProp.AsBoolValue()
}
