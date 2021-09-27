package parser

import (
	"fmt"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"os"
	"strings"
)

func ResolveJoin(property *Property) (resolved *Property) {
	if !property.isFunction() {
		return property
	}

	refValue := property.AsMap()["Fn::Join"].AsList()

	if len(refValue) != 2 {
		fmt.Fprintln(os.Stderr, "Fn::Join should have exactly 2 values, returning original Property")
		return property
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

	return &Property{
		name:        property.name,
		comment:     property.comment,
		rng:         property.rng,
		parentRange: property.parentRange,
		Inner: PropertyInner{
			Type:  cftypes.String,
			Value: joined,
		},
	}
}