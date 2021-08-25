package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/awslabs/goformation/v5"
)

type Parser struct{}

func New(filepaths ...string) (resource.Resources, error) {

	var resources resource.Resources
	for _, filepath := range filepaths {
		resourceRanges, err := GetResourceRangesForFile(filepath)
		if err != nil {
			return nil, err
		}

		template, err := goformation.Open(filepath)
		if err != nil {
			fmt.Printf("error occurred processing %s. %s", filepath, err.Error())
		}

		sourceFormat := resource.DefaultFormat
		if strings.HasSuffix(strings.ToLower(filepath), ".json") {
			sourceFormat = resource.JsonFormat
		}

		for name, r := range template.Resources {
			rng := resourceRanges[name]
			formationType := r.AWSCloudFormationType()
			resources = append(resources, resource.NewCFResource(&r, formationType, string(name), sourceFormat, filepath, rng))
		}
	}

	return resources, nil
}

func NewForDirectory(dirpath string) (resource.Resources, error) {
	if stat, err := os.Stat(dirpath); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("cannot use the provided filepath: %s", dirpath)
	}

	var files []string

	err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !includeFile(info.Name()) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return New(files...)
}

func includeFile(filename string) bool {
	for _, ext := range []string{".yml", ".yaml", ".json"} {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}
	return false
}
