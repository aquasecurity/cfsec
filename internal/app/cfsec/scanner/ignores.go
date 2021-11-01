package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
)

func isIgnored(result rules.Result) bool {
	if cfRef, ok := result.Reference().(*parser.CFReference); ok {
		prop := cfRef.ResolvedAttributeValue()
		if ignore, err := parseIgnore(prop.Comment()); err == nil {
			if ignore.RuleID != result.Rule().AVDID && ignore.RuleID != result.Rule().LongID() {
				return false
			}
			if ignore.Expiry == nil || time.Now().Before(*ignore.Expiry) {
				return true
			}
		}

	}
	return false
}

type Ignore struct {
	RuleID string
	Expiry *time.Time
}

func parseIgnore(comment string) (*Ignore, error) {

	comment = strings.TrimPrefix(comment, "#")
	comment = strings.TrimSpace(comment)

	var ignore Ignore
	if !strings.HasPrefix(comment, "cfsec:") {
		return nil, fmt.Errorf("invalid ignore")
	}

	comment = comment[6:]

	segments := strings.Split(comment, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			ignore.RuleID = val
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return nil, err
			}
			ignore.Expiry = &parsed
		}
	}

	return &ignore, nil
}
