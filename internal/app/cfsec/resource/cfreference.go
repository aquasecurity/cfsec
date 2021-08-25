package resource

import "github.com/aquasecurity/defsec/types"

type CFReference struct {
	resource Resource

	attribute string
}

func (cf *CFReference) String() string {
	panic("not implemented") // TODO: Implement
}

func (cf *CFReference) RefersTo(r types.Reference) bool {
	panic("not implemented") // TODO: Implement
}

func (cf *CFReference) Resource() Resource {
	return cf.resource
}

func (cf *CFReference) Attribute() string {
	return cf.attribute
}
