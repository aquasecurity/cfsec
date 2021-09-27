package parser

import (
	"encoding/base64"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

func ResolveBase64(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Base64"].AsString()
	retVal :=  base64.StdEncoding.EncodeToString([]byte(refValue))
	resolved = &Property{
		name:        property.name,
		comment:     property.comment,
		rng:         property.rng,
		parentRange: property.parentRange,
		Inner: PropertyInner{
			Type:  cftypes.String,
			Value: retVal,
		},
	}

	return resolved
}
