package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
)

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
		if index.CanBeConverted(cftypes.Int) {
			debug.Log("Converting index %v to Int", index.RawValue())
			index = index.ConvertTo(cftypes.Int)
		} else {
			return abortIntrinsic(property, "index on property [%s] should be an int, returning original Property", property.name)
		}
	}

	if list.IsNotList() {
		return abortIntrinsic(property, "list should be a list, returning original Property")
	}

	listItems := list.AsList()
	return listItems[index.AsInt()]
}
