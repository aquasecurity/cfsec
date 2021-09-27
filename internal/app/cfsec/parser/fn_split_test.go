package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

/*
	Fn::Split: ["::", "s3::bucket::to::split"]

 */

func Test_resolve_split_value(t *testing.T) {

	property := &Property{
		ctx: FileContext{},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Split": {
					Inner: PropertyInner{
						Type:  cftypes.List,
						Value: []*Property{
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "::",
								},
							},
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "s3::bucket::to::split",
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)
	assert.True(t, resolvedProperty.IsNotNil())
	assert.True(t, resolvedProperty.IsList())
	listContents := resolvedProperty.AsList()
	assert.Len(t,listContents, 4)

}