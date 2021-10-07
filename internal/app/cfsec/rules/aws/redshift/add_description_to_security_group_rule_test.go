package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/redshift"
)

func Test_CheckAddDescriptionToSecurityGroup_FailureExamples(t *testing.T) {
	expectedCode := redshift.CheckAddDescriptionToSecurityGroup.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckAddDescriptionToSecurityGroup_SuccessExamples(t *testing.T) {
	expectedCode := redshift.CheckAddDescriptionToSecurityGroup.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
