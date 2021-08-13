package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/awslabs/goformation/v5"
)

type Parser struct{}

func New(filepaths ...string) (resource.Resources, error) {

	var resources resource.Resources
	for _, filepath := range filepaths {
		template, err := goformation.Open(filepath)
		if err != nil {
			return nil, err
		}

		sourceFormat := resource.DefaultFormat
		if strings.HasSuffix(strings.ToLower(filepath), ".json") {
			sourceFormat = resource.JsonFormat
		}

		for name, r := range template.Resources {
			formationType := r.AWSCloudFormationType()
			resources = append(resources, resource.NewCFResource(&r, formationType, string(name), sourceFormat, filepath))
		}
	}

	return resources, nil
}
