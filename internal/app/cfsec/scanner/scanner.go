package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/pkg/result"
	"github.com/aquasecurity/defsec/rules"

	cfRules "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
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
func (scanner *Scanner) Scan(contexts parser.FileContexts) []result.Result {
	var results []result.Result
	for _, ctx := range contexts {
		state := adapter.Adapt(*ctx)
		for _, rule := range GetRegisteredRules() {
			debug.Log("Executing rule: %s", rule.LongID())
			evalResult := rule.Base.Evaluate(state)
			if len(evalResult) > 0 {
				debug.Log("Found %d results for %s", len(evalResult), rule.LongID())
				for _, scanResult := range evalResult {
					location := scanResult.Reference().(*parser.CFReference)

					if !isIgnored(scanResult) {
						description := getDescription(scanResult, location)
						addResult := result.Result{
							AVDID:       scanResult.Rule().AVDID,
							RuleID:      scanResult.Rule().LongID(),
							RuleSummary: scanResult.Rule().Summary,
							Impact:      scanResult.Rule().Impact,
							Resolution:  scanResult.Rule().Resolution,
							Links:       scanResult.Rule().Links,
							Description: description,
							Severity:    scanResult.Rule().Severity,
							Resource:    location.LogicalID(),
							Location: result.LocationBlock{
								Filename:  location.ResourceRange().GetFilename(),
								StartLine: location.ResourceRange().GetStartLine(),
								EndLine:   location.ResourceRange().GetEndLine(),
							},
							Status: scanResult.Status(),
						}
						addResult.SetProperty(location.ResolvedAttributeValue())
						if addResult.Status == rules.StatusPassed && !scanner.includePassed {
							continue
						}
						results = append(results, addResult)
					}
				}
			}
		}
	}
	return results
}

func getDescription(scanResult rules.Result, location *parser.CFReference) string {
	if scanResult.Status() != rules.StatusPassed {
		return scanResult.Description()
	}
	return fmt.Sprintf("Resource '%s' passed check: %s", location.LogicalID(), scanResult.Rule().Summary)
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
