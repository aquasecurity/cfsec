package parser

import (
	"github.com/aquasecurity/defsec/types"
)

// CFReference ...
type CFReference struct {
	logicalId string
	resourceRange types.Range
	resolvedValue Property
}

// NewCFReference ...
func NewCFReference(id string, resourceRange types.Range) types.Reference {
	return &CFReference{
		logicalId: id,
		resourceRange: resourceRange,
	}
}

// NewCFReferenceWithValue ...
func NewCFReferenceWithValue(resourceRange types.Range, resolvedValue Property, logicalId string) types.Reference {
	return &CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
		logicalId: logicalId,
	}
}

// String ...
func (cf *CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf *CFReference) LogicalID() string {
	return cf.logicalId
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
