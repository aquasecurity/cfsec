package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/cfsec/pkg/result"
)

// JSONOutput ...
type JSONOutput struct {
	Results []result.Result `json:"results"`
}

// FormatJSON ...
func FormatJSON(w io.Writer, results []result.Result, _ string, _ ...FormatterOption) error {
	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{results})
}
