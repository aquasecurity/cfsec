package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
)

// ResolveJoin ...
func ResolveJoin(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Join"].AsList()

	if len(refValue) != 2 {
		return abortIntrinsic(property, "Fn::Join should have exactly 2 values, returning original Property")
	}

	joiner := refValue[0].AsString()
	items := refValue[1].AsList()

	var itemValues []string
	for _, item := range items {
		resolved := item.resolveValue()
		if resolved.IsString() {
			itemValues = append(itemValues, resolved.AsString())
		}
	}

	joined := strings.Join(itemValues, joiner)

	return property.deriveResolved(cftypes.String, joined)
}
