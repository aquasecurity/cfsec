package main

import (
	"fmt"
	"os"

	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func main() {
	checks := scanner.GetRegisteredRules()
	fmt.Printf("Checks requiring linting: %d\n", len(checks))

	linter := &linter{}

	for _, check := range checks {
		linter.lint(check)
	}

	fmt.Printf("Checks requiring action:  %d\n", linter.count)
	os.Exit(linter.exitCode())
}
