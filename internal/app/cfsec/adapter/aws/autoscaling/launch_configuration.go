package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/autoscaling"
	"github.com/aquasecurity/defsec/types"
)

func getLaunchConfigurations(file parser.FileContext) (launchConfigurations []autoscaling.LaunchConfiguration) {
	launchConfigResources := file.GetResourceByType("AWS::AutoScaling::LaunchConfiguration")

	for _, r := range launchConfigResources {

		launchConfig := autoscaling.LaunchConfiguration{
			Name:              getName(r),
			AssociatePublicIP: hasPublicIPAssociated(r),
			EBSBlockDevices:   []autoscaling.BlockDevice{},
		}

		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			if i == 0 {
				launchConfig.RootBlockDevice = &device
				continue
			}
			launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, device)
		}

		launchConfigurations = append(launchConfigurations, launchConfig)

	}
	return launchConfigurations
}

func getBlockDevices(r *parser.Resource) []autoscaling.BlockDevice {
	var blockDevices []autoscaling.BlockDevice

	devicesProp := r.GetProperty("BlockDeviceMappings")

	if devicesProp.IsNil() {
		return blockDevices
	}

	for _, d := range devicesProp.AsList() {
		encrypted := d.GetProperty("Ebs.Encrypted")
		var result types.BoolValue
		if encrypted.IsNil() {
			result = types.BoolDefault(false, d.Metadata())
		} else {
			result = encrypted.AsBoolValue()
		}

		device := autoscaling.BlockDevice{
			Encrypted: result,
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}

func hasPublicIPAssociated(r *parser.Resource) types.BoolValue {
	publicIpProp := r.GetProperty("AssociatePublicIpAddress")
	if publicIpProp.IsNil() {
		return types.BoolDefault(false, r.Metadata())
	}

	if !publicIpProp.IsBool() {
		return types.BoolDefault(false, publicIpProp.Metadata())
	}
	return publicIpProp.AsBoolValue()
}

func getName(r *parser.Resource) types.StringValue {
	nameProp := r.GetProperty("Name")
	if nameProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}

	if !nameProp.IsString() {
		return types.StringDefault("", nameProp.Metadata())
	}

	return nameProp.AsStringValue()
}
