package test

import (
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
		results := scanTestSource(goodExample, t)
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
		results := scanTestSource(badExample, t)
		testutil.AssertCheckCode(t, rule.ID(), "", results)
	}
}

func scanTestSource(source string, t *testing.T) []rules.Result {

	fs, err := filesystem.New()
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.WriteTextFile("test.yaml", source); err != nil {
		t.Fatal(err)
	}

	path := fs.RealPath("test.yaml")

	fileCtx, err := parser.ParseFiles(path)
	if err != nil {
		t.Fatal(err)
	}

	s := scanner.New()
	return s.Scan(fileCtx)

}