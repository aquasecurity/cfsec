package parser

import "fmt"

type ErrNotCloudFormation struct {
	source string
}

func NewErrNotCloudFormation(source string) *ErrNotCloudFormation {
	return &ErrNotCloudFormation{
		source: source,
	}
}

func (e *ErrNotCloudFormation) Error() string {
	return fmt.Sprintf("The file %s is not CloudFormation", e.source)
}

type ErrInvalidContent struct {
	source string
	err    error
}

func NewErrInvalidContent(source string, err error) *ErrInvalidContent {
	return &ErrInvalidContent{
		source: source,
		err:    err,
	}
}
func (e *ErrInvalidContent) Error() string {
	return fmt.Sprintf("Invalid content in file: %s", e.source)
}

func (e *ErrInvalidContent) Reason() error {
	return e.err
}
