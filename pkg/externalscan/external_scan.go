package externalscan

import (
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/pkg/result"
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

func (t *ExternalScanner) Scan(toScan string) ([]result.Result, error) {
	fileContexts, err := parser.NewParser().ParseFiles(toScan)
	if err != nil {
		return nil, err
	}

	var results []result.Result
	internal := scanner.New(t.internalOptions...)

	results = append(results, internal.Scan(fileContexts)...)

	return results, nil
}
