package cloudtrail

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudtrail"
	"github.com/aquasecurity/defsec/types"
)

func getCloudTrails(ctx parser.FileContext) (trails []cloudtrail.Trail) {

	cloudtrailResources := ctx.GetResourceByType("AWS::CloudTrail::Trail")

	for _, r := range cloudtrailResources {
		ct := cloudtrail.Trail{
			Name:                    getTrailName(r),
			EnableLogFileValidation: hasLogValidation(r),
			IsMultiRegion:           isMultiRegion(r),
			KMSKeyID:                getKmsId(r),
		}

		trails = append(trails, ct)
	}

	return trails
}

func getKmsId(r *parser.Resource) types.StringValue {
	prop := r.GetProperty("KmsKeyId")

	if prop.IsNil() || !prop.IsString() {
		return types.StringDefault("", r.Metadata())
	}
	return prop.AsStringValue()
}

func isMultiRegion(r *parser.Resource) types.BoolValue {
	prop := r.GetProperty("IsMultiRegionTrail")

	if prop.IsNil() || !prop.IsBool(){
		return types.BoolDefault(false, r.Metadata())
	}
	return prop.AsBoolValue()
}

func hasLogValidation(r *parser.Resource) types.BoolValue {
	prop := r.GetProperty("EnableLogFileValidation")

	if prop.IsNil() || !prop.IsBool(){
		return types.BoolDefault(false, r.Metadata())
	}
	return prop.AsBoolValue()
}

func getTrailName(r *parser.Resource) types.StringValue {
	prop := r.GetProperty("TrailName")

	if prop.IsNil() || !prop.IsString() {
		return types.StringDefault("", r.Metadata())
	}
	return prop.AsStringValue()
}