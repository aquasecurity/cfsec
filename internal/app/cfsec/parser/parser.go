package parser

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

func ParseFiles(filepaths ...string) (FileContexts, error) {
	var contexts FileContexts
	for _, path := range filepaths {
		if err := func() error {
			debug.Log("Starting to process file %s", path)

			if _, err := os.Stat(path); err != nil {
				return err
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			context, err := Parse(file, path)
			if err != nil {
				return err
			}

			contexts = append(contexts, context)
			return nil
		}(); err != nil {
			return nil, err
		}
	}
	return contexts, nil
}

// Parse parses content from a io.Reader, which may not necessarily be a traditional file.
// the 'source' argument should identify the source of the content, be it a url, a filesystem path, a container etc.
func Parse(reader io.Reader, source string) (*FileContext, error) {

	sourceFmt := YamlSourceFormat
	if strings.HasSuffix(strings.ToLower(source), ".json") {
		sourceFmt = JsonSourceFormat
	}

	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	context := FileContext{
		filepath:     source,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	if strings.HasSuffix(strings.ToLower(source), ".json") {
		if err := jfather.Unmarshal(content, &context); err != nil {
			return nil, fmt.Errorf("source '%s' contains invalid JSON: %w", source, err)
		}
	} else {
		if err := yaml.Unmarshal(content, &context); err != nil {
			return nil, fmt.Errorf("source '%s' contains invalid YAML: %w", source, err)
		}
	}

	debug.Log("Context loaded from source %s", source)

	for name, r := range context.Resources {
		r.ConfigureResource(name, source, &context)
	}

	return &context, nil

}

func ParseDirectory(dir string) (FileContexts, error) {

	if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("cannot use the provided filepath: %s", dir)
	}

	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !includeFile(info.Name()) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return ParseFiles(files...)
}

func includeFile(filename string) bool {

	for _, ext := range []string{".yml", ".yaml", ".json"} {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}
	return false

}
