package externalscan

import (
	"fmt"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

type ExternalScanner struct {
	internalOptions []scanner.Option
}

func NewExternalScanner(options ...Option) *ExternalScanner {
	external := &ExternalScanner{}
	for _, option := range options {
		option(external)
	}
	return external
}

func (t *ExternalScanner) Scan(toScan string) ([]rules.FlatResult, error) {
	defer func() {
		if r := recover(); r != nil {
			debug.Log("error: %v", r)
			fmt.Printf("an error was encountered scanning %s\n", toScan)
		}
	}()
	fileContexts, err := parser.NewParser().ParseFiles(toScan)
	if err != nil {
		return nil, err
	}

	var results []rules.FlatResult
	internal := scanner.New(t.internalOptions...)

	for _, res := range internal.Scan(fileContexts) {
		results = append(results, res.Flatten())
	}

	return results, nil
}
