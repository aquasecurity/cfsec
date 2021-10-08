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

func (p *Property) Comment() string {
	return p.comment
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

	if p.IsMap() {
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
	ref := NewCFReferenceWithValue(p.parentRange, *p.resolveValue())
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
	return p.ctx.lines[p.rng.GetStartLine()-1 : p.rng.GetEndLine()], nil
}

func (p *Property) resolveValue() *Property {
	if !p.isFunction() {
		return p
	}

	return ResolveIntrinsicFunc(p)
}

func (p *Property) GetStringProperty(path string, defaultValue ...string) types.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := p.GetProperty(path)

	if prop.IsNotString() {
		return p.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

func (p *Property) GetBoolProperty(path string, defaultValue ...bool) types.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := p.GetProperty(path)

	if prop.IsNotBool() {
		return p.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

func (p *Property) GetIntProperty(path string, defaultValue ...int) types.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := p.GetProperty(path)

	if prop.IsNotInt() {
		return p.IntDefault(defVal)
	}
	return prop.AsIntValue()
}

func (p *Property) StringDefault(defaultValue string) types.StringValue {
	return types.StringDefault(defaultValue, p.Metadata())
}

func (p *Property) BoolDefault(defaultValue bool) types.BoolValue {
	return types.BoolDefault(defaultValue, p.Metadata())
}

func (p *Property) IntDefault(defaultValue int) types.IntValue {
	return types.IntDefault(defaultValue, p.Metadata())
}

// GetProperty takes a path to the property separated by '.' and returns
// the resolved value
func (p *Property) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	var property *Property

	if p.IsNotMap() {
		return nil
	}

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

func (p *Property) deriveResolved(propType cftypes.CfType, propValue interface{}) *Property {
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

func (p *Property) inferBool(prop *Property, defaultValue bool) types.BoolValue {
	if prop.IsString() {
		if prop.EqualTo("true", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("yes", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("1", IgnoreCase) {
			return types.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("false", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("no", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("0", IgnoreCase) {
			return types.Bool(false, prop.Metadata())
		}
	}

	if prop.IsInt() {
		if prop.EqualTo(0) {
			return types.Bool(false, prop.Metadata())
		}
		if prop.EqualTo(1) {
			return types.Bool(true, prop.Metadata())
		}
	}

	return p.BoolDefault(defaultValue)
}
