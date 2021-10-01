package parser

import (
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
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
	return property.deriveResolved(cftypes.Bool, propA.resolveValue().EqualTo(propB.resolveValue().RawValue()))

}