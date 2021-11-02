package parser

import (
	"errors"
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

type ErrNotCloudFormation struct {
	source string
}

func NewErrNotCloudFormation(source string) *ErrNotCloudFormation {
	return &ErrNotCloudFormation{
		source: source,
	}
}

func (e *ErrNotCloudFormation) Error() string{
	return fmt.Sprintf("The file %s is not CloudFormation", e.source)
}

// Parser ...
type Parser struct{
	parameters map[string]Parameter
}

func NewParser(options ...Option) *Parser {
	p := &Parser{}

	for _, option := range options {
		option(p)
	}

	return p
}

// ParseFiles ...
func (p *Parser) ParseFiles(filepaths ...string) (FileContexts, error) {
	var contexts FileContexts
	for _, path := range filepaths {
		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		if err := func() error {
			debug.Log("Starting to process file %s", path)

			if _, err := os.Stat(path); err != nil {
				return err
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() {_ =  file.Close()}()

			context, err := p.Parse(file, path)
			if err != nil {
				return err
			}

			contexts = append(contexts, context)
			return nil
		}(); err != nil {
			var err2 *ErrNotCloudFormation
			if errors.As(err, &err2) {
				debug.Log(err.Error())
				continue
			} else {
				return nil, err
			}
		}
	}
	return contexts, nil
}

// Parse parses content from an io.Reader, which may not necessarily be a traditional file.
// the 'source' argument should identify the source of the content, be it a url, a filesystem path, a container etc.
func (p *Parser) Parse(reader io.Reader, source string) (*FileContext, error) {

	sourceFmt := YamlSourceFormat
	if strings.HasSuffix(strings.ToLower(source), ".json") {
		sourceFmt = JsonSourceFormat
	}

	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	if !checkIsCloudformation(lines, sourceFmt) {
		return nil, NewErrNotCloudFormation(source)
	}

	context := &FileContext{
		filepath:     source,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	if strings.HasSuffix(strings.ToLower(source), ".json") {
		if err := jfather.Unmarshal(content, context); err != nil {
			return nil, fmt.Errorf("source '%s' contains invalid JSON: %w", source, err)
		}
	} else {
		if err := yaml.Unmarshal(content, context); err != nil {
			return nil, fmt.Errorf("source '%s' contains invalid YAML: %w", source, err)
		}
	}

	context.lines = lines
	context.SourceFormat = sourceFmt
	context.filepath = source

	debug.Log("Context loaded from source %s", source)

	for name, r := range context.Resources {
		r.ConfigureResource(name, source, context)
	}

	if p.parameters != nil {
		for name, passedParameter := range p.parameters {
			context.Parameters[name].UpdateDefault(passedParameter.Default())
		}
	}

	return context, nil

}

func checkIsCloudformation(lines []string, sourceFmt SourceFormat) bool {
	for _, line := range lines {
		switch sourceFmt {
		case YamlSourceFormat:
			if strings.Contains(line, "Resources:") {
				return true
			}
		case JsonSourceFormat:
			if strings.Contains(line, "\"Resources\"") {
				return true
			}
		}
	}

	return false
}

// ParseDirectory ...
func (p *Parser) ParseDirectory(dir string) (FileContexts, error) {

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

	return p.ParseFiles(files...)
}

func includeFile(filename string) bool {

	for _, ext := range []string{".yml", ".yaml", ".json"} {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}
	return false

}
