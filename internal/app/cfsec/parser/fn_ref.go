package parser

import "github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"

func ResolveReference(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}
	refValue := property.AsMap()["Ref"].AsString()
	var param *Parameter
	for k := range property.ctx.Parameters {
		if k == refValue {
			param = property.ctx.Parameters[k]
			return &Property{
				name:        property.name,
				comment:     property.comment,
				rng:         property.rng,
				parentRange: property.parentRange,
				Inner: PropertyInner{
					Type:  param.Type(),
					Value: param.Default(),
				},
			}
		}
	}
	for k := range property.ctx.Resources {
		if k == refValue {
			res := property.ctx.Resources[k]
			return &Property{
				name:        property.name,
				comment:     property.comment,
				rng:         property.rng,
				parentRange: property.parentRange,
				Inner: PropertyInner{
					Type:  cftypes.String,
					Value: res.ID(),
				},
			}
		}
	}
	return nil
}
