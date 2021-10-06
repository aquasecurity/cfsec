package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Redshift_AddDescriptionToSecurityGroup_FailureExamples(t *testing.T) {
	expectedCode := "aws-redshift-add-description-to-security-group"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Redshift_AddDescriptionToSecurityGroup_SuccessExamples(t *testing.T) {
	expectedCode := "aws-redshift-add-description-to-security-group"
	test.RunPassingExamplesTest(t, expectedCode)
}
