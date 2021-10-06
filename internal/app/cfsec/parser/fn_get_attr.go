package parser

import (
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

func ResolveGetAtt(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValueProp := property.AsMap()["Fn::GetAtt"]

	if refValueProp.IsNotList() {
		fmt.Fprintln(os.Stderr, "Fn::Equals should have exactly 2 values, returning original Property")
		return property
	}

	refValue := refValueProp.AsList()

	if len(refValue) != 2 {
		fmt.Fprintln(os.Stderr, "Fn::Equals should have exactly 2 values, returning original Property")
		return property
	}

	logicalId := refValue[0]
	attribute := refValue[1]

	referencedResource := property.ctx.GetResourceByName(logicalId.AsString())
	if referencedResource.IsNil() {
		return property
	}

	referencedProperty := referencedResource.GetProperty(attribute.AsString())
	if referencedProperty.IsNil() {
		// if the attribute value can't be found, just return the ID for the resource
		return property.deriveResolved(cftypes.String, referencedResource.ID())
	}

	return property.deriveResolved(referencedProperty.Type(), referencedProperty)
}
