package misc

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS044",
		Service:   "misc",
		ShortCode: "no-exposing-plaintext-credentials",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
provider "aws" {
  access_key = "AKIAABCD12ABCDEF1ABC"
  secret_key = "s8d7ghas9dghd9ophgs9"
}
`},
			GoodExample: []string{`
provider "aws" {
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs#argument-reference",
				"https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html",
			},
		},

		RequiredTypes:   []string{"provider"},
		RequiredLabels:  []string{"aws"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
