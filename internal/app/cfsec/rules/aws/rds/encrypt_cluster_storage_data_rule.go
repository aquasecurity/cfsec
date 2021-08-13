package rds

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
		LegacyID:  "AWS051",
		Service:   "rds",
		ShortCode: "encrypt-cluster-storage-data",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_rds_cluster" "bad_example" {
  name       = "bar"
  kms_key_id = ""
}`},
			GoodExample: []string{`
resource "aws_rds_cluster" "good_example" {
  name              = "bar"
  kms_key_id  = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  storage_encrypted = true
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_rds_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
