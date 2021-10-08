package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

// Parameter ...
type Parameter struct {
	inner parameterInner
}

type parameterInner struct {
	Type    string      `yaml:"Type"`
	Default interface{} `yaml:"Default"`
}

// UnmarshalYAML ...
func (p *Parameter) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.inner)
}

// UnmarshalJSONWithMetadata ...
func (p *Parameter) UnmarshalJSONWithMetadata(node jfather.Node) error {
	return node.Decode(&p.inner)
}

// Type ...
func (p *Parameter) Type() cftypes.CfType {
	switch p.inner.Type {
	case "Boolean":
		return cftypes.Bool
	case "String":
		return cftypes.String
	default:
		return cftypes.String
	}
}

// Default ...
func (p *Parameter) Default() interface{} {
	return p.inner.Default
}
