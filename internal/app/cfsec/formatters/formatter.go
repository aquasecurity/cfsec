package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
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
type Formatter func(w io.Writer, results []rules.Result, baseDir string, options ...FormatterOption) error
