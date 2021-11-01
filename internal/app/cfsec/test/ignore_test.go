package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	internalRules "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
)

func Test_IgnoreRules_Basic(t *testing.T) {

	ruleID := registerExampleRule()
	defer scanner.DeregisterRuleByID(ruleID)

	code := fmt.Sprintf(`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: evil #cfsec:ignore:%s
`, ruleID)

	ctx, err := parser.NewParser().Parse(strings.NewReader(code), "test.yaml")
	if err != nil {
		t.Fatalf("Failed to parse YAML:\n\n%s\n\nError: %s", code, err)
	}
	results := scanner.New().Scan([]*parser.FileContext{ctx})
	for _, result := range results {
		if result.RuleID == ruleID {
			t.Fatalf("Result was found but should not have been")
		}
	}
}

func Test_IgnoreRules_NotExpired(t *testing.T) {

	ruleID := registerExampleRule()
	defer scanner.DeregisterRuleByID(ruleID)

	code := fmt.Sprintf(`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: evil #cfsec:ignore:%s:exp:%s
`, ruleID, time.Now().Add(time.Hour*24).Format("2006-01-02"))

	ctx, err := parser.NewParser().Parse(strings.NewReader(code), "test.yaml")
	if err != nil {
		t.Fatalf("Failed to parse YAML:\n\n%s\n\nError: %s", code, err)
	}
	results := scanner.New().Scan([]*parser.FileContext{ctx})
	for _, result := range results {
		if result.RuleID == ruleID {
			t.Fatalf("Result was found but should not have been")
		}
	}
}

func Test_IgnoreRules_Expired(t *testing.T) {

	ruleID := registerExampleRule()
	defer scanner.DeregisterRuleByID(ruleID)

	code := fmt.Sprintf(`---
Resources:
  BadExample:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: evil #cfsec:ignore:%s:exp:%s
`, ruleID, time.Now().Add(-time.Hour*24).Format("2006-01-02"))

	ctx, err := parser.NewParser().Parse(strings.NewReader(code), "test.yaml")
	if err != nil {
		t.Fatalf("Failed to parse YAML:\n\n%s\n\nError: %s", code, err)
	}
	results := scanner.New().Scan([]*parser.FileContext{ctx})
	var found bool
	for _, result := range results {
		if result.RuleID == ruleID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Result was not found but should have been")
	}
}

func registerExampleRule() string {
	example := internalRules.Rule{
		Base: rules.Register(
			rules.Rule{
				AVDID:     "ABCDEFG",
				Provider:  "testcloud",
				Service:   "badvms",
				ShortCode: "checksomething",
			},
			func(s *state.State) (results rules.Results) {
				for _, bucket := range s.AWS.S3.Buckets {
					if bucket.Name.Contains("evil") {
						results.Add(
							"Bucket appears to be evil.",
							bucket.Name,
						)
					}
				}
				return
			},
		),
	}

	scanner.RegisterCheckRule(example)
	return example.LongID()
}
