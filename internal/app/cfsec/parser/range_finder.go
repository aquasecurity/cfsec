package parser

import (
	"encoding/json"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/awslabs/goformation/v5/intrinsics"
	"github.com/sanathkr/yaml"
)

type template struct {
	Resources map[string]interface{} `json:"Resources,omitempty"`
}

func GetResourceRangesForFile(filepath string) (map[string]types.Range, error) {

	resourceRange := make(map[string]types.Range)

	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(b), "\n")
	fileLength := len(lines)

	var rawContent []byte
	format := "yaml"
	if strings.HasSuffix(filepath, ".json") {
		rawContent, err = intrinsics.ProcessJSON(b, &intrinsics.ProcessorOptions{NoProcess: true})
		format = "json"
	} else {
		rawContent, err = intrinsics.ProcessYAML(b, &intrinsics.ProcessorOptions{NoProcess: true})
	}

	if err != nil {
		return nil, err
	}

	var rawTemplate template
	if err := json.Unmarshal(rawContent, &rawTemplate); err != nil {
		return nil, err
	}

	for name, resource := range rawTemplate.Resources {

		s, err := getStrings(name, format, resource)
		if err != nil {
			return nil, err
		}

		resLength := len(s)
		for i := range lines {
			if i+resLength > fileLength {
				break
			}

			if blockFound(lines[i:i+resLength], s) {
				resourceRange[name] = types.NewRange(filepath, i+1, i+resLength)
			}
		}

	}

	return resourceRange, nil
}

func getStrings(resourceName, format string, content interface{}) ([]string, error) {

	marshalStruct := map[string]interface{}{
		resourceName: content,
	}

	output, err := json.MarshalIndent(marshalStruct, "", "  ")
	if err != nil {
		return nil, err
	}
	var resourceStrings []string

	if format == "json" {
		parts := strings.Split(string(output), "\n")
		for i, l := range parts {
			if i == 0 || i == len(parts)-1 {
				continue
			}
			if l == "" {
				continue
			}
			resourceStrings = append(resourceStrings, l)
		}
	} else {

		y, err := yaml.JSONToYAML(output)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(string(y), "\n") {
			if l == "" {
				continue
			}
			resourceStrings = append(resourceStrings, l)

		}
	}
	return resourceStrings, nil
}

func blockFound(lines, resource []string) bool {

	if strings.TrimSpace(lines[0]) != strings.TrimSpace(resource[0]) {
		return false
	}

	left := prepareBlocksForComparison(lines)
	right := prepareBlocksForComparison(resource)

	for i := 0; i < len(right); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func prepareBlocksForComparison(in []string) []string {

	var out []string

	for _, s := range in {
		s = strings.TrimPrefix(strings.TrimSpace(strings.ReplaceAll(s, "'", "")), "- ")
		s = strings.TrimSuffix(s, ",")
		out = append(out, strings.TrimSpace(s))
	}
	sort.Strings(out)
	return out
}
