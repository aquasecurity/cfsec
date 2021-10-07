package main

import (
	"fmt"
	"math"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
)

type linter struct {
	count int
}

func (l *linter) lint(check rules.Rule) {

	errorFound := l.checkDocumentation(check)
	if errorFound {
		l.count += 1
	}
}

func (l *linter) checkDocumentation(check rules.Rule) bool {
	var errorFound bool

	for _, goodExample := range check.GoodExample {
		if err := l.verifyPart(goodExample, "GoodExample"); err != nil {
			fmt.Printf("%s: %s\n", check.ID(), err.Error())
			errorFound = true
		}
	}
	for _, badExample := range check.BadExample {
		if err := l.verifyPart(badExample, "BadExample"); err != nil {
			fmt.Printf("%s: %s\n", check.ID(), err.Error())
			errorFound = true
		}
	}

	if len(check.Base.Rule().Links) == 0 && len(check.Links) == 0 {
		fmt.Printf("%s: Has no links configure\n", check.ID())
		errorFound = true
	}
	return errorFound
}

func (l *linter) verifyPart(checkPart, checkDescription string) error {
	if strings.TrimSpace(checkPart) == "" {
		return fmt.Errorf("[%s] documentation is empty", checkDescription)
	}

	return nil
}

func (l *linter) exitCode() int {
	return int(math.Min(1, float64(l.count)))
}
