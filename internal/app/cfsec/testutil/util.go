package testutil

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/testutil/filesystem"
	"github.com/aquasecurity/defsec/rules"
	"github.com/stretchr/testify/assert"
)

// TestFileExt ...
type TestFileExt string

// YamlTestFileExt ...
const (
	YamlTestFileExt TestFileExt = "yaml"
	JsonTestFileExt TestFileExt = "json"
)

// AssertCheckCode ...
func AssertCheckCode(t *testing.T, includeCode string, excludeCode string, results []rules.Result) {

	var foundInclude bool
	var foundExclude bool

	var excludeText string

	for _, res := range results {
		if res.Rule().LongID() == excludeCode {
			foundExclude = true
			excludeText = res.Description()
		}
		if res.Rule().LongID() == includeCode {
			foundInclude = true
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been: %s", excludeCode, excludeText))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been", includeCode))
	}
}

// CreateTestFile ...
func CreateTestFile(source string, ext TestFileExt) string {
	testFiles, err := filesystem.New()
	if err != nil {
		panic(err)
	}

	testFile := fmt.Sprintf("testfile.%s", ext)
	if err := testFiles.WriteFile(testFile, []byte(source)); err != nil {
		panic(err)
	}

	return testFiles.RealPath(testFile)
}
