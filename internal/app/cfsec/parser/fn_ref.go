package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

// ResolveReference ...
func ResolveReference(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refProp := property.AsMap()["Ref"]
	if refProp.IsNotString() {
		return property, false
	}
	refValue := refProp.AsString()

	if pseudo, ok := pseudoParameters[refValue]; ok {
		return property.deriveResolved(cftypes.String, pseudo.(string)), true
	}

	var param *Parameter
	for k := range property.ctx.Parameters {
		if k == refValue {
			param = property.ctx.Parameters[k]
			resolved = property.deriveResolved(param.Type(), param.Default())
			return resolved, true
		}
	}

	for k := range property.ctx.Resources {
		if k == refValue {
			res := property.ctx.Resources[k]
			resolved = property.deriveResolved(cftypes.String, res.ID())
			break
		}
	}
	return resolved, true
}

