package parser

import (
	"fmt"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"os"
)

func ResolveEquals(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Equals"].AsList()

	if len(refValue) != 2 {
		fmt.Fprintln(os.Stderr, "Fn::Equals should have exactly 2 values, returning original Property")
		return property
	}

	propA := refValue[0]
	propB := refValue[1]


	return &Property{
		name:        property.name,
		comment:     property.comment,
		rng:         property.rng,
		parentRange: property.parentRange,
		Inner: PropertyInner{
			Type:  cftypes.Bool,
			Value: propA.resolveValue().EqualTo(propB.resolveValue().RawValue()),
		},
	}
}