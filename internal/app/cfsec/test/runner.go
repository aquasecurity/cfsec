package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/testutil"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/testutil/filesystem"
	"github.com/aquasecurity/defsec/rules"
)

func RunPassingExamplesTest(t *testing.T, expectedCode string) {

	rule, err := scanner.GetRuleById(expectedCode)

	if err != nil {
		t.Fatalf("Rule not found: %s", expectedCode)
	}
	for i, goodExample := range rule.GoodExample {
		t.Logf("Running good example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(goodExample) == "" {
			t.Fatalf("Good example code not provided for %s", rule.ID())
		}
		results, err := scanTestSource(goodExample, t)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertCheckCode(t, "", rule.ID(), results)
	}

}

func RunFailureExamplesTest(t *testing.T, expectedCode string) {

	rule, err := scanner.GetRuleById(expectedCode)

	if err != nil {
		t.Fatalf("Rule not found: %s", expectedCode)
	}
	for i, badExample := range rule.BadExample {
		t.Logf("Running bad example for '%s' #%d", expectedCode, i+1)
		if strings.TrimSpace(badExample) == "" {
			t.Fatalf("bad example code not provided for %s", rule.ID())
		}
		results, err := scanTestSource(badExample, t)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertCheckCode(t, rule.ID(), "", results)
	}
}

func scanTestSource(source string, t *testing.T) ([]rules.Result, error) {

	fs, err := filesystem.New()
	if err != nil {
		return nil, err
	}
	defer fs.Close()

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

	fileCtx, err := parser.ParseFiles(path)
	if err != nil {
		return nil, err
	}

	s := scanner.New()
	return s.Scan(fileCtx), nil

}
