package iam

// generator-locked
import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

type PolicyDocument struct {
	Statements []awsIAMPolicyDocumentStatement `json:"Statement"`
}

type awsIAMPolicyDocumentStatement struct {
	Effect    string                    `json:"Effect"`
	Action    awsIAMPolicyDocumentValue `json:"Action"`
	Resource  awsIAMPolicyDocumentValue `json:"Resource,omitempty"`
	Principal awsIAMPolicyPrincipal     `json:"Principal,omitempty"`
}

type awsIAMPolicyPrincipal struct {
	AWS     []string
	Service []string
}

// AWS allows string or []string as value, we convert everything to []string to avoid casting
type awsIAMPolicyDocumentValue []string

func (value *awsIAMPolicyPrincipal) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case map[string]interface{}:
		for key, each := range v {
			switch raw := each.(type) {
			case string:
				if key == "Service" {
					value.Service = append(value.Service, raw)
				} else {
					value.AWS = append(value.AWS, raw)
				}
			case []string:
				if key == "Service" {
					value.Service = append(value.Service, raw...)
				} else {
					value.AWS = append(value.AWS, raw...)
				}
			}
		}
	case string:
		value.AWS = []string{v}
	case []interface{}:
		for _, item := range v {
			value.AWS = append(value.AWS, fmt.Sprintf("%v", item))
		}
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	return nil
}

func (value *awsIAMPolicyDocumentValue) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	var p []string
	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case string:
		p = []string{v}
	case []interface{}:
		var items []string
		for _, item := range v {
			items = append(items, fmt.Sprintf("%v", item))
		}
		p = items
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	*value = p
	return nil
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS097",
		Service:   "iam",
		ShortCode: "block-kms-policy-wildcard",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id

	policy = data.aws_iam_policy_document.kms_policy.json
}

resource "aws_iam_role" "test_role" {
	name = "test_role"
	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [
		{
			Action = "sts:AssumeRole"
			Effect = "Allow"
			Sid    = ""
			Principal = {
			Service = "ec2.amazonaws.com"
			}
		},
		]
	})
}

data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

`},
			GoodExample: []string{`
resource "aws_kms_key" "main" {
	enable_key_rotation = true
}

resource "aws_iam_role_policy" "test_policy" {
	name = "test_policy"
	role = aws_iam_role.test_role.id
  
	policy = data.aws_iam_policy_document.kms_policy.json
}

resource "aws_iam_role" "test_role" {
	name = "test_role"
	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [
		{
			Action = "sts:AssumeRole"
			Effect = "Allow"
			Sid    = ""
			Principal = {
			Service = "ec2.amazonaws.com"
			}
		},
		]
	})
}

data "aws_iam_policy_document" "kms_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = [aws_kms_key.main.arn]
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document",
				"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-kms-1",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_policy", "aws_iam_group_policy", "aws_iam_user_policy", "aws_iam_role_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
