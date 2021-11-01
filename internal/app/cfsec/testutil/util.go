package testutil

import (
	"fmt"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/testutil/filesystem"
)

// TestFileExt ...
type TestFileExt string

// YamlTestFileExt ...
const (
	YamlTestFileExt TestFileExt = "yaml"
	JsonTestFileExt TestFileExt = "json"
)


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
