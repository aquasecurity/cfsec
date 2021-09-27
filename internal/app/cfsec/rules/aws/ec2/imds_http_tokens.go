package ec2

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ec2"
)

func init() {

	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{`---
`},
		GoodExample: []string{`---
`},
		Base: ec2.CheckIMDSAccessRequiresToken,
	})

}
