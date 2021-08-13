package testutil

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func ScanHCL(source string, t *testing.T, additionalOptions ...scanner.Option) []result.Result {

	var results []result.Result

	return results

}
