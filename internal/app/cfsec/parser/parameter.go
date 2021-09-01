package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Parameter struct {
	inner parameterInner
}

type parameterInner struct {
	Type    string      `yaml:"Type"`
	Default interface{} `yaml:"Default"`
}

func (p *Parameter) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.inner)
}

func (p *Parameter) UnmarshalJSONWithMetadata(node jfather.Node) error {
	return node.Decode(&p.inner)
}

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

func (p *Parameter) Default() interface{} {
	return p.inner.Default
}
