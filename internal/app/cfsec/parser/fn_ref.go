package parser

func ResolveReference(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Ref"].AsString()

	var param *Parameter
	for k := range property.ctx.Parameters {
		if k == refValue {
			param = property.ctx.Parameters[k]
			break
		}
	}

	if param != nil {
		resolved = &Property{
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

	return resolved
}