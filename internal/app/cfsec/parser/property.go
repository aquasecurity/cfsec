package parser

import (

	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type EqualityOptions = int

const (
	IgnoreCase EqualityOptions = iota
)

type Property struct {
	ctx         *FileContext
	name        string
	comment     string
	rng         types.Range
	parentRange types.Range
	Inner       PropertyInner
}

type PropertyInner struct {
	Type  cftypes.CfType
	Value interface{} `json:"Value" yaml:"Value"`
}

func (p *Property) setName(name string) {
	p.name = name
	if p.Type() == cftypes.Map {
		for n, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setName(n)
		}
	}
}

func (p *Property) setContext(ctx *FileContext) {
	p.ctx = ctx

	if p.IsMap(){
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setContext(ctx)
		}
	}

	if p.IsList() {
		for _, subProp := range p.AsList() {
			subProp.setContext(ctx)
		}
	}
}

// setFileAndParentRange updates the Property and all nested properties with the resource range and filepath
func (p *Property) setFileAndParentRange(filepath string, parentRange types.Range) {
	p.rng = types.NewRange(filepath, p.rng.GetStartLine(), p.rng.GetEndLine())
	p.parentRange = parentRange

	switch p.Type() {
	case cftypes.Map:
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(filepath, parentRange)
		}
	case cftypes.List:
		for _, subProp := range p.AsList() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(filepath, parentRange)
		}
	}
}

func (p *Property) UnmarshalYAML(node *yaml.Node) error {
	p.rng = types.NewRange("", node.Line, calculateEndLine(node))

	p.comment = node.LineComment
	return setPropertyValueFromYaml(node, &p.Inner)
}

func (p *Property) UnmarshalJSONWithMetadata(node jfather.Node) error {
	p.rng = types.NewRange("", node.Range().Start.Line, node.Range().End.Line)
	return setPropertyValueFromJson(node, &p.Inner)
}

func (p *Property) Type() cftypes.CfType {
	return p.Inner.Type
}

func (p *Property) Range() types.Range {
	return p.rng
}
func (p *Property) Metadata() types.Metadata {
	ref := NewCFReference(p.parentRange)
	return types.NewMetadata(p.Range(), ref)
}

func (p *Property) MetadataWithValue(resolvedValue *Property) types.Metadata {
	ref := NewCFReferenceWithValue(p.parentRange, *resolvedValue)
	return types.NewMetadata(p.Range(), ref)
}

func (p *Property) isFunction() bool {
	if p.Type() == cftypes.Map {
		for n := range p.AsMap() {
			return IsIntrinsic(n)
		}
	}
	return false
}

// RawValue returns the value as an interface
func (p *Property) RawValue() interface{} {
	return p.Inner.Value
}

func (p *Property) AsRawStrings() ([]string, error) {
	return p.ctx.lines[p.rng.GetStartLine()-1:p.rng.GetEndLine()], nil
}

func (p *Property) resolveValue() *Property {
	if !p.isFunction() {
		return p
	}

	return ResolveIntrinsicFunc(p)
}

// GetProperty takes a path to the property separated by '.' and returns
// the resolved value
func (p *Property) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	var property *Property

	for n, p := range p.AsMap() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 || property == nil {
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty.resolveValue()
	}

	return nil
}

func (p *Property) deriveResolved( propType cftypes.CfType, propValue interface{}) *Property {
	return &Property{
		ctx:         p.ctx,
		name:        p.name,
		comment:     p.comment,
		rng:         p.rng,
		parentRange: p.parentRange,
		Inner: PropertyInner{
			Type:  propType,
			Value: propValue,
		},
	}
}