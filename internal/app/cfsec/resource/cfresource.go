package resource

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"github.com/awslabs/goformation/v5/cloudformation"
	"github.com/awslabs/goformation/v5/intrinsics"
	"github.com/sanathkr/yaml"
)

type SourceFormat string

const (
	DefaultFormat SourceFormat = YamlFormat
	YamlFormat    SourceFormat = "yaml"
	JsonFormat    SourceFormat = "json"
)

type CFResource struct {
	resource     *cloudformation.Resource
	resourceType string
	resourceName string
	sourceFormat SourceFormat
	filepath     string
}

func NewCFResource(resource *cloudformation.Resource, resourceType string, resourceName string, sourceFormat SourceFormat, filepath string) Resource {
	return &CFResource{
		resource:     resource,
		resourceType: resourceType,
		resourceName: resourceName,
		filepath:     filepath,
		sourceFormat: sourceFormat,
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

func (r *CFResource) Filepath() string {
	wd, err := os.Getwd()
	if err != nil {
		wd = ""
	}
	return path.Join(wd, r.filepath)
}

func (r *CFResource) Render() (string, error) {

	jsonContent, err := getResolvedContent(r.filepath, r.resourceName, r.sourceFormat)
	if err != nil {
		return "", err
	}

	marshalStruct := map[string]interface{}{
		r.resourceName: jsonContent,
	}

	output, err := json.MarshalIndent(marshalStruct, "", "  ")
	if err != nil {
		return "", err
	}
	if r.sourceFormat == JsonFormat {
		return string(output), nil
	}

	y, err := yaml.JSONToYAML(output)
	if err != nil {
		return "", err
	}
	return string(y), nil
}

func getResolvedContent(filepath, resourceName string, format SourceFormat) (interface{}, error) {

	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var content []byte

	if format == JsonFormat {
		content, err = intrinsics.ProcessJSON(b, nil)
	} else {
		content, err = intrinsics.ProcessYAML(b, nil)
	}

	if err != nil {
		return nil, err
	}

	var t template
	if err := json.Unmarshal(content, &t); err != nil {
		return nil, err
	}

	for n, r := range t.Resources {
		if n == resourceName {
			return r, nil
		}
	}

	return "", nil
}

type template struct {
	Resources map[string]interface{} `json:"Resources,omitempty"`
}
