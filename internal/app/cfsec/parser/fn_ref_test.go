package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_resolve_referenced_value(t *testing.T) {

	property := &Property{
		ctx: &FileContext{
			filepath: "",
			Parameters: map[string]*Parameter{
				"BucketName": {
					inner: parameterInner{
						Type:    "string",
						Default: "someBucketName",
					},
				},
			},
		},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Ref": {
					Inner: PropertyInner{
						Type:  cftypes.String,
						Value: "BucketName",
					},
				},
			},
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.Equal(t, "someBucketName", resolvedProperty.AsString())
}

func Test_property_value_correct_when_not_reference(t *testing.T) {

	property := &Property{
		ctx: &FileContext{
			filepath: "",
		},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.String,
			Value: "someBucketName",
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.Equal(t, "someBucketName", resolvedProperty.AsString())
}