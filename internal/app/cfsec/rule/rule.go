package rule

import "github.com/aquasecurity/defsec/rules"

type Rule struct {
	Base rules.RegisteredRule

	// BadExample (yaml) contains CloudFormation code which would cause the check to fail
	BadExample []string

	// GoodExample (yaml) contains CloudFormation code which would pass the check
	GoodExample []string

	// Additional links for further reading about the check
	Links []string
}

func (r Rule) ID() string {
	return r.Base.Rule().LongID()
}
