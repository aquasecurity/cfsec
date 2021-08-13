package resource

import "github.com/awslabs/goformation/v5/cloudformation"

type CFResource struct {
	resource     *cloudformation.Resource
	resourceType string
	resourceName string
}

func NewCFResource(resource *cloudformation.Resource, resourceType string, resourceName string) Resource {
	return &CFResource{
		resource:     resource,
		resourceType: resourceType,
		resourceName: resourceName,
	}
}

func (r *CFResource) Type() string {
	return r.resourceType
}

func (r *CFResource) Underlying() cloudformation.Resource {
	return *r.resource
}

func (r *CFResource) IsNil() bool {
	return r.resource == nil
}

func (r *CFResource) Name() string {
	return r.resourceName
}
