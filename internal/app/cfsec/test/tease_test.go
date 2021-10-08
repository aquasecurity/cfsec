package test

import (
	"strings"
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func Test_PanicTeasing(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {
		for _, code := range append(mutateYAML(rule.BadExample...), mutateYAML(rule.GoodExample...)...) {
			func() {
				defer func() {
					if err := recover(); err != nil {
						t.Fatalf("Panic encountered for code:\n\n%s\n\nPanic: %s", code, err)
					}
				}()
				ctx, err := parser.Parse(strings.NewReader(code), "test.yaml")
				if err != nil {
					t.Fatalf("Failed to parse YAML:\n\n%s\n\nError: %s", code, err)
				}
				state := adapter.Adapt(*ctx)
				_ = rule.Base.Evaluate(state)
			}()
		}
	}

}

func mutateYAML(input ...string) []string {
	return input
}
