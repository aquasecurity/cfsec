package externalscan

import (
	"path/filepath"

	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/pkg/result"
)

type ExternalScanner struct {
	paths           []string
	internalOptions []scanner.Option
}

func NewExternalScanner(options ...Option) *ExternalScanner {
	external := &ExternalScanner{}
	for _, option := range options {
		option(external)
	}
	return external
}

func (t *ExternalScanner) AddPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	t.paths = append(t.paths, abs)
	return nil
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
