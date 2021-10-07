package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func Test_CheckAddDescriptionToSecurityGroupRule_FailureExamples(t *testing.T) {
	expectedCode := vpc.CheckAddDescriptionToSecurityGroupRule.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckAddDescriptionToSecurityGroupRule_PassedExamples(t *testing.T) {
	expectedCode := vpc.CheckAddDescriptionToSecurityGroupRule.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
