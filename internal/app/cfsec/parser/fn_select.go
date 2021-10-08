package parser

// ResolveSelect attempts to resolve the value from a Fn::Select with a Property
func ResolveSelect(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Select"].AsList()

	if len(refValue) != 2 {
		abortIntrinsic(property, "Fn::Select should have exactly 2 values, returning original Property")
		return property
	}

	index := refValue[0]
	list := refValue[1]

	if index.IsNotInt() || list.IsNotList() {

	}
	// return property.deriveResolved(cftypes.Bool, index.resolveValue().EqualTo(propB.resolveValue().RawValue()))


	return property
}
