package parser

import "github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"

func ResolveReference(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refProp := property.AsMap()["Ref"]
	if refProp.IsNotString() {
		return property
	}
	refValue := refProp.AsString()
	var param *Parameter
	for k := range property.ctx.Parameters {
		if k == refValue {
			param = property.ctx.Parameters[k]
			resolved = property.deriveResolved(param.Type(), param.Default())
			return resolved
		}
	}

	for k := range property.ctx.Resources {
		if k == refValue {
			res := property.ctx.Resources[k]
			resolved = property.deriveResolved(cftypes.String, res.ID())
			break
		}
	}
	return resolved
}
