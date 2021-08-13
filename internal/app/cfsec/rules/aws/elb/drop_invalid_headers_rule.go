package elb

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
		LegacyID:  "AWS083",
		Service:   "elb",
		ShortCode: "drop-invalid-headers",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_alb" "bad_example" {
	name               = "bad_alb"
	internal           = false
	load_balancer_type = "application"
	
	access_logs {
	  bucket  = aws_s3_bucket.lb_logs.bucket
	  prefix  = "test-lb"
	  enabled = true
	}
  
	drop_invalid_header_fields = false
  }
`},
			GoodExample: []string{`
resource "aws_alb" "good_example" {
	name               = "good_alb"
	internal           = false
	load_balancer_type = "application"
	
	access_logs {
	  bucket  = aws_s3_bucket.lb_logs.bucket
	  prefix  = "test-lb"
	  enabled = true
	}
  
	drop_invalid_header_fields = true
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields",
				"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_alb", "aws_lb"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
