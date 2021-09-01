package parser

import (
	"github.com/aquasecurity/defsec/types"
)

type CFReference struct {
	resourceRange types.Range
	resolvedValue Property
}

func NewCFReference(resourceRange types.Range) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange types.Range, resolvedValue Property) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
	}
}

func (cf *CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf *CFReference) RefersTo(r types.Reference) bool {
	return false
}

func (cf *CFReference) ResourceRange() types.Range {
	return cf.resourceRange
}

func (cf *CFReference) ResolvedAttributeValue() interface{} {
	return cf.resolvedValue
}
