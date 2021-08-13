package ecs

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
		LegacyID:  "AWS096",
		Service:   "ecs",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_ecs_task_definition" "bad_example" {
	family                = "service"
	container_definitions = file("task-definitions/service.json")
  
	volume {
	  name = "service-storage"
  
	  efs_volume_configuration {
		file_system_id          = aws_efs_file_system.fs.id
		root_directory          = "/opt/data"
		authorization_config {
		  access_point_id = aws_efs_access_point.test.id
		  iam             = "ENABLED"
		}
	  }
	}
  }
`},
			GoodExample: []string{`
resource "aws_ecs_task_definition" "good_example" {
	family                = "service"
	container_definitions = file("task-definitions/service.json")
  
	volume {
	  name = "service-storage"
  
	  efs_volume_configuration {
		file_system_id          = aws_efs_file_system.fs.id
		root_directory          = "/opt/data"
		transit_encryption      = "ENABLED"
		transit_encryption_port = 2999
		authorization_config {
		  access_point_id = aws_efs_access_point.test.id
		  iam             = "ENABLED"
		}
	  }
	}
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition#transit_encryption",
				"https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html",
				"https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_task_definition"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
