package parser

import (
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Resource struct {
	rng     types.Range
	id      string
	comment string
	Inner   ResourceInner
}

type ResourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) Fixup(id, filepath string) {
	r.setId(id)
	r.setFile(filepath)
}

func (r *Resource) setId(id string) {
	r.id = id

	for n, p := range r.Properties() {
		p.setName(n)
	}

}

func (r *Resource) setFile(filepath string) {
	r.rng = types.NewRange(filepath, r.rng.GetStartLine(), r.rng.GetEndLine())

	for _, p := range r.Inner.Properties {
		p.setFileAndParentRange(filepath, r.rng)
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

func (r *Resource) Metadata() *types.Metadata {
	return types.NewMetadata(r.Range(), NewCFReference(r.rng))
}

func (r *Resource) Properties() map[string]*Property {
	return r.Inner.Properties
}

func (r *Resource) GetPropertyForPath(path string) *Property {
	return r.GetProperty(strings.Split(path, ".")...)
}

func (r *Resource) GetProperty(pathParts ...string) *Property {

	first := pathParts[0]
	var property *Property

	for n, p := range r.Properties() {
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
