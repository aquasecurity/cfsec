package parser

import (
	"github.com/aquasecurity/defsec/types"
)

// CFReference ...
type CFReference struct {
	resourceRange types.Range
	resolvedValue Property
}

// NewCFReference ...
func NewCFReference(resourceRange types.Range) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
	}
}

// NewCFReferenceWithValue ...
func NewCFReferenceWithValue(resourceRange types.Range, resolvedValue Property) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
	}
}

// String ...
func (cf *CFReference) String() string {
	return cf.resourceRange.String()
}

// RefersTo ...
func (cf *CFReference) RefersTo(r types.Reference) bool {
	return false
}

// ResourceRange ...
func (cf *CFReference) ResourceRange() types.Range {
	return cf.resourceRange
}

// ResolvedAttributeValue ...
func (cf *CFReference) ResolvedAttributeValue() Property {
	return cf.resolvedValue
}
