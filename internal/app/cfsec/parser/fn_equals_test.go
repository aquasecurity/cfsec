package parser

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func Test_resolve_equals_value(t *testing.T) {

	property := &Property{
		ctx: &FileContext{},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type:  cftypes.List,
						Value: []*Property{
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.True(t,resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_to_false(t *testing.T) {

	property := &Property{
		ctx: &FileContext{},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type:  cftypes.List,
						Value: []*Property{
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "foo",
								},
							},
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "bar",
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.False(t,resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_to_true_when_boolean(t *testing.T) {

	property := &Property{
		ctx: &FileContext{},
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type:  cftypes.List,
						Value: []*Property{
							{
								Inner:       PropertyInner{
									Type:  cftypes.Bool,
									Value: true,
								},
							},
							{
								Inner:       PropertyInner{
									Type:  cftypes.Bool,
									Value: true,
								},
							},
						},
					},
				},
			},
		},
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.True(t,resolvedProperty.IsTrue())
}

func Test_resolve_equals_value_when_one_is_a_reference(t *testing.T) {

	property := &Property{
		name:        "BucketName",
		rng:         types.NewRange("testfile", 1, 1),
		Inner: PropertyInner{
			Type: cftypes.Map,
			Value: map[string]*Property{
				"Fn::Equals": {
					Inner: PropertyInner{
						Type:  cftypes.List,
						Value: []*Property{
							{
								Inner:       PropertyInner{
									Type:  cftypes.String,
									Value: "staging",
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
	}

	resolvedProperty := ResolveIntrinsicFunc(property)

	assert.True(t,resolvedProperty.IsTrue())
}