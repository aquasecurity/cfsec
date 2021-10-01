package parser

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func Test_resolve_join_value(t *testing.T) {

	property := &Property{
		ctx:  &FileContext{},
		name: "BucketName",
		rng:  types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Join": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "::",
								},
							},
							{
								Inner: PropertyInner{
									Type: cftypes.List,
									Value: []*Property{
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "s3",
											},
										},
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "part1",
											},
										},
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "part2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.Equal(t, "s3::part1::part2", resolvedProperty.AsString())
}

func Test_resolve_join_value_with_reference(t *testing.T) {

	property := &Property{
		ctx: &FileContext{
			filepath: "",
			Parameters: map[string]*Parameter{
				"Environment": {
					inner: parameterInner{
						Type:    "string",
						Default: "staging",
					},
				},
			},
		},
		name: "EnvironmentBucket",
		rng:  types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Join": {
					Inner: PropertyInner{
						Type: cftypes.List,
						Value: []*Property{
							{
								Inner: PropertyInner{
									Type:  cftypes.String,
									Value: "::",
								},
							},
							{
								Inner: PropertyInner{
									Type: cftypes.List,
									Value: []*Property{
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "s3",
											},
										},
										{
											Inner: PropertyInner{
												Type:  cftypes.String,
												Value: "part1",
											},
										},
										{
											ctx: &FileContext{
												filepath: "",
												Parameters: map[string]*Parameter{
													"Environment": {
														inner: parameterInner{
															Type:    "string",
															Default: "staging",
														},
													},
												},
											},
											Inner: PropertyInner{
												Type: cftypes.Map,
												Value: map[string]*Property{
													"Ref": {
														Inner: PropertyInner{
															Type:  cftypes.String,
															Value: "Environment",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
		resolvedProperty := ResolveIntrinsicFunc(property)

		assert.Equal(t, "s3::part1::staging", resolvedProperty.AsString())
	}
