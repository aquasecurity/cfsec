package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/rules"
)

// JSONOutput ...
type JSONOutput struct {
	Results []rules.FlatResult `json:"results"`
}

// FormatJSON ...
func FormatJSON(w io.Writer, results []rules.Result, _ string, _ ...FormatterOption) error {
	var flattened []rules.FlatResult

	for _, result := range results {
		flattened = append(flattened, result.Flatten())
	}

	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{flattened})
}
