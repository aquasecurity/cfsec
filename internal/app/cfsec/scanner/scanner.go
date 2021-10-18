package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"

	cfRules "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
)


var ruleMu sync.Mutex
var registeredRules []cfRules.Rule

func RegisterCheckRule(rules ...cfRules.Rule) {
	for i, rule := range rules {
		cfsecLink := fmt.Sprintf("https://cfsec.dev/docs/%s/%s/#%s", rule.Base.Rule().Service, rule.Base.Rule().ShortCode, rule.Base.Rule().Service)
		rules[i].Base.AddLink(cfsecLink)
	}


	ruleMu.Lock()
	defer ruleMu.Unlock()
	registeredRules = append(registeredRules, rules...)
}

func DeregisterRuleByID(id string) {
	ruleMu.Lock()
	defer ruleMu.Unlock()
	var filtered []cfRules.Rule
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
			debug.Log("Executing rule: %s", rule.LongID())
			evalResult := rule.Base.Evaluate(state)
			if len(evalResult) > 0 {
				debug.Log("Found %d results for %s", len(evalResult), rule.LongID())
			}
			for _, result := range evalResult {
				if !isIgnored(result) {
					results = append(results, result)
				}
			}
		}
	}
	return results
}

// GetRegisteredRules provides all Checks which have been registered with this package

func GetRegisteredRules() []cfRules.Rule {
	sort.Slice(registeredRules, func(i, j int) bool {
		return registeredRules[i].ID() < registeredRules[j].ID()
	})
	return registeredRules
}

// GetRuleByLongID ...
func GetRuleByLongID(long string) (*cfRules.Rule, error) {

	for _, r := range registeredRules {
		if r.LongID() == long {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("could not find rule with long ID '%s'", long)
}
