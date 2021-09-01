package testutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules"
	"github.com/stretchr/testify/assert"
)

func ScanHCL(source string, t *testing.T, additionalOptions ...scanner.Option) []rules.Result {

	var results []rules.Result

	return results

}

func AssertCheckCode(t *testing.T, includeCode string, excludeCode string, results []rules.Result, messages ...string) {

	var foundInclude bool
	var foundExclude bool

	var excludeText string

	for _, res := range results {
		if res.Rule().ID == excludeCode {
			foundExclude = true
			excludeText = res.Description()
		}
		if res.Rule().ID == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been: %s", excludeCode, excludeText))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been", includeCode))
	}
}

func CreateTestFileWithModule(contents string, moduleContents string) string {
	dir, err := ioutil.TempDir(os.TempDir(), "tfsec")
	if err != nil {
		panic(err)
	}

	rootPath := filepath.Join(dir, "main")
	modulePath := filepath.Join(dir, "module")

	if err := os.Mkdir(rootPath, 0755); err != nil {
		panic(err)
	}

	if err := os.Mkdir(modulePath, 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(rootPath, "main.tf"), []byte(contents), 0755); err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filepath.Join(modulePath, "main.tf"), []byte(moduleContents), 0755); err != nil {
		panic(err)
	}

	return rootPath
}
