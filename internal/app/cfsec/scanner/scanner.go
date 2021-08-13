package scanner

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
)

var registeredRules []rule.Rule

func RegisterCheckRule(rule rule.Rule) {
	registeredRules = append(registeredRules, rule)
}

type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
	}
	for _, option := range options {
		option(s)
	}
	return s
}
func (scanner *Scanner) Scan(resources resource.Resources) []result.Result {

	var results []result.Result

	for _, r := range registeredRules {
		for _, b := range resources {
			for _, t := range r.RequiredTypes {
				if t == b.Type() {
					resultSet := result.NewSet(b).
						WithRuleID(r.ID()).
						WithLinks(r.Documentation.Links).
						WithLocation(b.Filepath())

					r.CheckFunc(resultSet, b)
					for _, result := range resultSet.All() {
						if result.Severity == severity.None {
							result.Severity = r.DefaultSeverity
						}
						results = append(results, *result)

					}
				}
			}
		}
	}

	return results
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []rule.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

func GetRuleById(ID string) (*rule.Rule, error) {
	for _, r := range registeredRules {
		if r.ID() == ID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with legacyID '%s'", ID)
}

func GetRuleByLegacyID(legacyID string) (*rule.Rule, error) {
	for _, r := range registeredRules {
		if r.LegacyID == legacyID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with legacyID '%s'", legacyID)
}
