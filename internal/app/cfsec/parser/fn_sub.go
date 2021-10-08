package parser

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)



// ResolveSub attempts to resolve the value of a string with substitutions with a Property
func ResolveSub(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Sub"]

	if refValue.IsString() {
		return resolveStringSub(refValue, property)
	}

	if refValue.IsList() {
		return resolveMapSub(refValue, property)
	}

	return property
}

func resolveMapSub(refValue *Property, original *Property) *Property {
	refValues := refValue.AsList()
	if len(refValues) != 2 {
		return abortIntrinsic(original, "Fn::Sub with list expects 2 values, returning original property")
	}

	workingString := refValues[0].AsString()
	components := refValues[1].AsMap()

	for k, v := range components {
		workingString = strings.ReplaceAll(workingString, fmt.Sprintf("${%s}", k), v.AsString())
	}

	return original.deriveResolved(cftypes.String, workingString)
}

func resolveStringSub(refValue *Property, original *Property) *Property {
	workingString := refValue.AsString()

	for k, v := range pseudoParameters {
		workingString = strings.ReplaceAll(workingString, fmt.Sprintf("${%s}", k), fmt.Sprintf("%v", v))
	}

	return original.deriveResolved(cftypes.String, workingString)
}
