package parser

import (
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Resource struct {
	ctx *FileContext
	rng     types.Range
	id      string
	comment string
	Inner   ResourceInner
}

type ResourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) ConfigureResource(id, filepath string, ctx *FileContext) {
	r.setId(id)
	r.setFile(filepath)
	r.setContext(ctx)
}

func (r *Resource) setId(id string) {
	r.id = id

	for n, p := range r.properties() {
		p.setName(n)
	}

}

func (r *Resource) setFile(filepath string) {
	r.rng = types.NewRange(filepath, r.rng.GetStartLine(), r.rng.GetEndLine())

	for _, p := range r.Inner.Properties {
		p.setFileAndParentRange(filepath, r.rng)
	}
}

func (r *Resource) setContext(ctx *FileContext) {
	r.ctx = ctx

	for _, p := range r.Inner.Properties {
		p.setContext(ctx)
	}
}

func (r *Resource) UnmarshalYAML(value *yaml.Node) error {
	r.rng = types.NewRange("", value.Line-1, calculateEndLine(value))
	r.comment = value.LineComment
	return value.Decode(&r.Inner)
}

func (r *Resource) UnmarshalJSONWithMetadata(node jfather.Node) error {
	r.rng = types.NewRange("", node.Range().Start.Line, node.Range().End.Line)
	return node.Decode(&r.Inner)
}

func (r *Resource) ID() string {
	return r.id
}

func (r *Resource) Type() string {
	return r.Inner.Type
}

func (r *Resource) Range() types.Range {
	return r.rng
}

func (r *Resource) SourceFormat() SourceFormat {
	return r.ctx.SourceFormat
}

func (r *Resource) Metadata() types.Metadata {
	return types.NewMetadata(r.Range(), NewCFReference(r.rng))
}

func (r *Resource) properties() map[string]*Property {
	return r.Inner.Properties
}

func (r *Resource) IsNil() bool {
	return r.id == ""
}

// GetProperty takes a path to the property separated by '.' and returns
// the resolved value
func (r *Resource) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := &Property{}

	for n, p := range r.properties() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 || property.IsNil() {
		return property.resolveValue()
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty
	}

	return &Property{}
}

func (r *Resource) StringDefault(defaultValue string) types.StringValue {
	return types.StringDefault(defaultValue, r.Metadata())
}

func (r *Resource) BoolDefault(defaultValue bool) types.BoolValue {
	return types.BoolDefault(defaultValue, r.Metadata())
}

func (r *Resource) IntDefault(defaultValue int) types.IntValue {
	return types.IntDefault(defaultValue, r.Metadata())
}