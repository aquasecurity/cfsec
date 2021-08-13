package resource

import "github.com/awslabs/goformation/v5/cloudformation"

type Resource interface {
	Type() string
	Underlying() cloudformation.Resource
	IsNil() bool
	Name() string
	Render() (string, error)
	Filepath() string
}
