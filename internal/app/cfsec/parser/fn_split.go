package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

func ResolveSplit(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Split"].AsList()

	if len(refValue) != 2 {
		fmt.Fprintln(os.Stderr, "Fn::Split should have exactly 2 values, returning original Property")
		return property
	}

	delimiterProp := refValue[0]
	splitProp := refValue[1]

	if !splitProp.IsString() || !delimiterProp.IsString() {
		fmt.Fprintf(os.Stderr, "Fn::Split requires two strings as input, returning original Property")
		return property
	}

	propertyList := createPropertyList(splitProp, delimiterProp, property)

	return property.deriveResolved(cftypes.List, propertyList)
}

func createPropertyList(splitProp *Property, delimiterProp *Property, parent *Property) []*Property {

	splitString := splitProp.AsString()
	delimiter := delimiterProp.AsString()

	splits := strings.Split(splitString, delimiter)
	var props []*Property
	for _, split := range splits {
		props = append(props, parent.deriveResolved(cftypes.String, split))
	}
	return props
}