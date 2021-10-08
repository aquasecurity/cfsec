package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	internalRules "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
)

var ruleMu sync.Mutex
var registeredRules []internalRules.Rule

func RegisterCheckRule(rules ...internalRules.Rule) {
	ruleMu.Lock()
	defer ruleMu.Unlock()
	registeredRules = append(registeredRules, rules...)
}

func DeregisterRuleByID(id string) {
	ruleMu.Lock()
	defer ruleMu.Unlock()
	var filtered []internalRules.Rule
	for _, rule := range registeredRules {
		if rule.ID() == id {
			continue
		}
		filtered = append(filtered, rule)
	}
	registeredRules = filtered
}


// Scanner ...
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

// Scan ...
func (scanner *Scanner) Scan(contexts parser.FileContexts) []rules.Result {
	var results []rules.Result
	for _, ctx := range contexts {
		state := adapter.Adapt(*ctx)
		for _, rule := range GetRegisteredRules() {
			for _, result := range rule.Base.Evaluate(state) {
				if !isIgnored(result) {
					results = append(results, result)
				}
			}
		}
	}
	return results
}

// GetRegisteredRules provides all Checks which have been registered with this package
func GetRegisteredRules() []internalRules.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

func GetRuleByLongID(long string) (*internalRules.Rule, error) {
	for _, r := range registeredRules {
		if r.LongID() == long {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with long ID '%s'", long)
}
