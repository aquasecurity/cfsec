package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

// ResolveGetAtt ...
func ResolveGetAtt(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValueProp := property.AsMap()["Fn::GetAtt"]

	var refValue []string

	if refValueProp.IsString() {
		refValue = strings.Split(refValueProp.AsString(), ".")
	}

	if refValueProp.IsList() {
		for _, p := range refValueProp.AsList() {
			refValue = append(refValue, p.AsString())
		}
	}

	if len(refValue) != 2 {
		fmt.Fprintln(os.Stderr, "Fn::GetAtt should have exactly 2 values, returning original Property")
		return property
	}

	logicalId := refValue[0]
	attribute := refValue[1]

	referencedResource := property.ctx.GetResourceByName(logicalId)
	if referencedResource == nil || referencedResource.IsNil() {
		return property.deriveResolved(cftypes.String, "")
	}

	referencedProperty := referencedResource.GetProperty(attribute)
	if referencedProperty.IsNil() {
		// if the attribute value can't be found, just return the ID for the resource
		return property.deriveResolved(cftypes.String, referencedResource.ID())
	}

	return property.deriveResolved(referencedProperty.Type(), referencedProperty)
}
