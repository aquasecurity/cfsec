package parser


// ResolveSelect attempts to resolve the value from a Fn::Select with a Property
func ResolveSelect(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Select"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Select should have exactly 2 values, returning original Property")
	}

	index := refValue[0]
	list := refValue[1]


	if index.IsNotInt() {
		return abortIntrinsic(property, "index should be an int, returning original Property")
	}

	if list.IsNotList() {
		return abortIntrinsic(property, "list should be a list, returning original Property")
	}

	return list.AsList()[index.AsInt()-1]
}
