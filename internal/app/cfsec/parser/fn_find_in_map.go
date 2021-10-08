package parser

import (
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

func ResolveFindInMap(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::FindInMap"].AsList()

	if len(refValue) != 3 {
		return abortFindInMap(property, "Fn::FindInMap should have exactly 3 values, returning original Property")
	}

	mapName := refValue[0].AsString()
	topLevelKey := refValue[1].AsString()
	secondaryLevelKey := refValue[2].AsString()

	if property.ctx == nil {
		return abortFindInMap(property, "the property does not have an attached context, returning original Property")
	}

	m, ok := property.ctx.Mappings[mapName]
	if !ok {
		return abortFindInMap(property, "could not find map %s, returning original Property")
	}

	mapContents := m.(map[string]interface{})

	k , ok := mapContents[topLevelKey]
	if !ok {
		return abortFindInMap(property, "could not find %s in the %s map, returning original Property", topLevelKey, mapName)
	}

	mapValues := k.(map[string]interface{})

	if prop, ok := mapValues[secondaryLevelKey]; !ok {
		return abortFindInMap(property, "could not find a value for %s in %s, returning original Property", secondaryLevelKey, topLevelKey)
	} else {
		return property.deriveResolved(cftypes.String, prop)
	}


}


func abortFindInMap(property *Property, msg string, components ...string) *Property {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(msg, components))
	return property
}