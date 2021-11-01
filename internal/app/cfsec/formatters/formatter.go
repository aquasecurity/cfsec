package formatters

import (
	"io"

	"github.com/aquasecurity/cfsec/pkg/result"
)

// FormatterOption ...
type FormatterOption int

// ConciseOutput ...
const (
	ConciseOutput FormatterOption = iota
	IncludePassed
	PassingGif
)

// Formatter formats scan results into a specific format
type Formatter func(w io.Writer, results []result.Result, scanPath string, options ...FormatterOption) error
