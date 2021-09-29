package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Property struct {
	ctx         FileContext
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

func (p *Property) setContext(ctx FileContext) {
	p.ctx = ctx

	if p.Type() == cftypes.Map {
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
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

func (p *Property) resolveValue() *Property {
	if !p.isFunction() {
		return p
	}

	return ResolveIntrinsicFunc(p)
}

func (p *Property) IsNil() bool {
	return p == nil || p.Inner.Value == nil
}

func (p *Property) IsNotNil() bool {
	return !p.IsNil()
}

func (p *Property) IsString() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.String
}

func (p *Property) IsNotString() bool {
	return !p.IsString()
}

func (p *Property) IsMap() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.Map
}

func (p *Property) IsNotMap() bool {
	return !p.IsMap()
}

func (p *Property) IsList() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.List
}

func (p *Property) IsNotList() bool {
	return !p.IsList()
}

func (p *Property) IsBool() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.Bool
}

func (p *Property) IsNotBool() bool {
	return !p.IsBool()
}

func (p *Property) AsString() string {
	return p.Inner.Value.(string)
}

func (p *Property) AsStringValue() types.StringValue {
	return types.StringExplicit(p.AsString(), p.Metadata())
}

func (p *Property) AsBool() bool {
	return p.Inner.Value.(bool)
}

func (p *Property) AsBoolValue() types.BoolValue {
	return types.Bool(p.AsBool(), p.Metadata())
}

func (p *Property) AsMap() map[string]*Property {
	return p.Inner.Value.(map[string]*Property)
}

func (p *Property) AsList() []*Property {
	return p.Inner.Value.([]*Property)
}

func (p *Property) EqualTo(checkValue interface{}) bool {
	if p.IsNil() {
		return checkValue == nil
	}

	if p.RawValue() == checkValue {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == checkValue.(string)
	default:
		return false
	}
}

func (p *Property) IsTrue() bool {
	if p.IsNil() || !p.IsBool() {
		return false
	}

	return p.AsBool()
}

func (p *Property) IsEmpty() bool {

	if p.IsNil() {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
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
