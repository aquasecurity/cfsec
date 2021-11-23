package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/rules"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/testutil/filesystem"
	"github.com/stretchr/testify/require"
)

// RunPassingExamplesTest ...
func RunPassingExamplesTest(t *testing.T, expectedCode string) {

	rule, err := scanner.GetRuleByLongID(expectedCode)

	if err != nil {
		t.Fatalf("Rule not found: %s", expectedCode)
	}
	for i, goodExample := range rule.GoodExample {
		t.Logf("Running good example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(goodExample) == "" {
			t.Fatalf("Good example code not provided for %s", rule.ID())
		}

		results := scanTestSource(t, goodExample)
		assertCheckCode(t, "", rule.LongID(), results)
	}

}

// RunFailureExamplesTest ...
func RunFailureExamplesTest(t *testing.T, expectedCode string) {

	rule, err := scanner.GetRuleByLongID(expectedCode)

	if err != nil {
		t.Fatalf("Rule not found: %s", expectedCode)
	}
	for i, badExample := range rule.BadExample {
		t.Logf("Running bad example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(badExample) == "" {
			t.Fatalf("bad example code not provided for %s", rule.ID())
		}
		results := scanTestSource(t, badExample)

		assertCheckCode(t, rule.LongID(), "", results)
	}
}

func scanTestSource(t *testing.T, source string) []rules.Result {
	fileCtx, err := CreateFileContexts(t, source)
	require.NoError(t, err)
	s := scanner.New()
	return s.Scan(fileCtx)
}

// CreateFileContexts ...
func CreateFileContexts(_ *testing.T, source string) (parser.FileContexts, error) {
	fs, err := filesystem.New()
	if err != nil {
		return nil, err
	}
	defer func() { _ = fs.Close() }()

	ext := "yaml"
	if source[0] == '{' {
		ext = "json"
	} else if strings.Contains(source, "\t") {
		return nil, fmt.Errorf("source yaml contains tab characters - please replace them:\n%q\n\n", source)
	}

	filename := fmt.Sprintf("test.%s", ext)

	if err := fs.WriteTextFile(filename, source); err != nil {
		return nil, err
	}

	path := fs.RealPath(filename)

	fileCtx, err := parser.NewParser().ParseFiles(path)
	if err != nil {
		return nil, err
	}
	return fileCtx, nil

}

func assertCheckCode(t *testing.T, includeCode string, excludeCode string, results []rules.Result) {

	var foundInclude bool
	var foundExclude bool

	for _, res := range results {
		if res.Rule().LongID() == excludeCode {
			foundExclude = true
		}
		if res.Rule().LongID() == includeCode {
			foundInclude = true
			assert.Greater(t, res.NarrowestRange().GetStartLine(), 0)
		}
	}

	assert.False(t, foundExclude, fmt.Sprintf("res with code '%s' was found but should not have been", excludeCode))
	if includeCode != "" {
		assert.True(t, foundInclude, fmt.Sprintf("res with code '%s' was not found but should have been", includeCode))
	}
}
