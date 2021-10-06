package parser

import (
	"io/ioutil"
	"strings"
)

type SourceFormat string

const (
	YamlSourceFormat SourceFormat = "yaml"
	JsonSourceFormat SourceFormat = "json"
)

type FileContexts []*FileContext

type FileContext struct {
	filepath     string
	lines []string
	SourceFormat SourceFormat
	Parameters   map[string]*Parameter  `json:"Parameters" yaml:"Parameters"`
	Resources    map[string]*Resource   `json:"Resources" yaml:"Resources"`
	Globals      map[string]*Resource   `json:"Globals" yaml:"Globals"`
	Mappings     map[string]interface{} `json:"Mappings,omitempty" yaml:"Mappings"`
}

func newFileContext(filepath string) *FileContext {
	sourceFmt := YamlSourceFormat
	if strings.HasSuffix(strings.ToLower(filepath), ".json") {
		sourceFmt = JsonSourceFormat
	}

	lines, err := getLines(filepath)
	if err != nil {
		lines = []string{}
	}

	return &FileContext{
		filepath:     filepath,
		lines: lines ,
		SourceFormat: sourceFmt,
	}
}

func getLines(filepath string) ([]string, error) {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}

func (t *FileContext) GetResourceByName(name string) *Resource {
	for n, r := range t.Resources {
		if name == n {
			return r
		}
	}
	return nil
}

func (t *FileContext) GetResourceByType(names ...string) []*Resource {

	var resources []*Resource
	for _, r := range t.Resources {
		for _, name := range names {
			if name == r.Type() {
				resources = append(resources, r)
			}
		}
	}
	return resources
}
