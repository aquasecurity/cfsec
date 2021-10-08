package parser

import (
	"encoding/base64"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

// ResolveBase64 ...
func ResolveBase64(property *Property) *Property {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Base64"].AsString()
	retVal := base64.StdEncoding.EncodeToString([]byte(refValue))

	return property.deriveResolved(cftypes.String, retVal)
}
