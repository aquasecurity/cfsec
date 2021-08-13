package codebuild

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
		LegacyID:  "AWS080",
		Service:   "codebuild",
		ShortCode: "enable-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_codebuild_project" "bad_example" {
	// other config

	artifacts {
		// other artifacts config

		encryption_disabled = true
	}
}

resource "aws_codebuild_project" "bad_example" {
	// other config including primary artifacts

	secondary_artifacts {
		// other artifacts config
		
		encryption_disabled = false
	}

	secondary_artifacts {
		// other artifacts config

		encryption_disabled = true
	}
}
`},
			GoodExample: []string{`
resource "aws_codebuild_project" "good_example" {
	// other config

	artifacts {
		// other artifacts config

		encryption_disabled = false
	}
}

resource "aws_codebuild_project" "good_example" {
	// other config

	artifacts {
		// other artifacts config
	}
}

resource "aws_codebuild_project" "codebuild" {
	// other config

	secondary_artifacts {
		// other artifacts config

		encryption_disabled = false
	}

	secondary_artifacts {
		// other artifacts config
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_codebuild_project"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
