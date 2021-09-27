package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Parser struct{}

func ParseFiles(filepaths ...string) (FileContexts, error) {

	var contexts FileContexts

	for _, path := range filepaths {

		if _, err := os.Stat(path); err != nil {
			return nil, err
		}

		fileContent, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		context := newFileContext(path)

		if strings.HasSuffix(strings.ToLower(path), ".json") {
			if err := jfather.Unmarshal(fileContent, &context); err != nil {
				return nil, err
			}
		} else {
			if err := yaml.Unmarshal(fileContent, &context); err != nil {
				return nil, err
			}
		}

		for name, r := range context.Resources {
			r.ConfigureResource(name, path, context)
		}

		contexts = append(contexts, context)
	}

	return contexts, nil
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
