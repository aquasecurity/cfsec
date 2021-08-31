package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Property struct {
	name        string
	comment     string
	rng         types.Range
	parentRange types.Range
	inner       propertyInner
}

type propertyInner struct {
	Type  cftypes.CfType
	Value interface{} `json: "Value" yaml:"Value"`
}

func (p *Property) setName(name string) {
	p.name = name
	if p.Type() == cftypes.Map {
		for n, p := range p.AsMap() {
			p.setName(n)
		}
	}
}

// setFileAndParentRange updates the Property and all nested properties with the resource range and filepath
func (p *Property) setFileAndParentRange(filepath string, parentRange types.Range) {
	p.rng = types.NewRange(filepath, p.rng.GetStartLine(), p.rng.GetEndLine())
	p.parentRange = parentRange

	switch p.Type() {
	case cftypes.Map:
		for _, p := range p.AsMap() {
			p.setFileAndParentRange(filepath, parentRange)
		}
	case cftypes.List:
		for _, p := range p.AsList() {
			p.setFileAndParentRange(filepath, parentRange)
		}
	}
}

func (p *Property) UnmarshalYAML(node *yaml.Node) error {
	p.rng = types.NewRange("", node.Line, calculateEndLine(node))

	p.comment = node.LineComment
	return setPropertyValue(node, &p.inner)
}

func (p *Property) UnmarshalJSONWithMetadata(node jfather.Node) error {
	p.rng = types.NewRange("", node.Range().Start.Line, node.Range().End.Line)
	return node.Decode(&p.inner)
}

func (p *Property) Type() cftypes.CfType {
	return p.inner.Type
}

func (p *Property) Range() types.Range {
	return p.rng
}
func (p *Property) Metadata() *types.Metadata {
	ref := NewCFReference(p.parentRange)
	return types.NewMetadata(p.Range(), ref)
}

func (p *Property) MetadataWithValue(resolvedValue Property) *types.Metadata {
	ref := NewCFReferenceWithValue(p.parentRange, resolvedValue)
	return types.NewMetadata(p.Range(), ref)
}

func (p *Property) IsReference() bool {
	if p.Type() == cftypes.Map {
		for n := range p.AsMap() {
			return n == "Ref"
		}
	}
	return false
}

// RawValue returns the value as an interface
func (p *Property) RawValue() interface{} {
	return p.inner.Value
}

// ResolveValue used to get the referenced value
func (p *Property) ResolveValue(ctx FileContext) Property {
	if !p.IsReference() {
		return *p
	}

	refValue := p.AsMap()["Ref"].AsString()

	var param *Parameter
	for k := range ctx.Parameters {
		if k == refValue {
			param = ctx.Parameters[k]
			break
		}
	}

	if param != nil {

		return Property{
			name:        p.name,
			comment:     p.comment,
			rng:         p.rng,
			parentRange: p.parentRange,
			inner: propertyInner{
				Type:  param.Type(),
				Value: param.Default(),
			},
		}
	}

	empty := *p

	empty.inner.Value = nil
	return empty

}

func (p *Property) IsNil() bool {
	return p.inner.Value == nil
}

func (p *Property) IsNotNil() bool {
	return !p.IsNil()
}

func (p *Property) AsString() string {
	return p.inner.Value.(string)
}

func (p *Property) AsBool() bool {
	return p.inner.Value.(bool)
}

func (p *Property) AsMap() map[string]*Property {
	return p.inner.Value.(map[string]*Property)
}

func (p *Property) AsList() []*Property {
	return p.inner.Value.([]*Property)
}

func (r *Property) GetProperty(pathParts ...string) *Property {

	first := pathParts[0]
	var property *Property

	for n, p := range r.AsMap() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 {
		return property
	}

	if nestedProperty := property.GetProperty(pathParts[1:]...); nestedProperty != nil {
		return nestedProperty
	}

	return nil
}
