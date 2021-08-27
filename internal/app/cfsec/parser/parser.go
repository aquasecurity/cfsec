package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parser struct{}

func ParseFiles(filepaths ...string) (FileContexts, error) {

	var contexts []FileContext

	for _, filepath := range filepaths {

		if _, err := os.Stat(filepath); err != nil {
			return nil, err
		}

		fileContent, err := ioutil.ReadFile(filepath)
		if err != nil {
			return nil, err
		}

		context := newFileContext(filepath)

		if strings.HasSuffix(strings.ToLower(filepath), ".json") {

		} else {
			if err := yaml.Unmarshal(fileContent, &context); err != nil {
				return nil, err
			}

			for name, r := range context.Resources {
				r.Fixup(name, filepath)
			}

			contexts = append(contexts, context)
		}
	}

	return contexts, nil
}

func ParseDirectory(dirpath string) (FileContexts, error) {
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
