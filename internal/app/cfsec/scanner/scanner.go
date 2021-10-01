package scanner

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
)

var registeredRules []rule.Rule

func RegisterCheckRule(rules ...rule.Rule) {
	registeredRules = append(registeredRules, rules...)
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
func (scanner *Scanner) Scan(contexts parser.FileContexts) []rules.Result {

	var results []rules.Result

	for _, ctx := range contexts {

		state := adapter.Adapt(*ctx)

		for _, rule := range GetRegisteredRules() {

			results = append(results, rule.Base.Evaluate(state)...)
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
