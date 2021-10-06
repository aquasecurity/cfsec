package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Redshift_NoClassicResources_FailureExamples(t *testing.T) {
	expectedCode := "aws-redshift-no-classic-resources"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Redshift_NoClassicResources_SuccessExamples(t *testing.T) {
	expectedCode := "aws-redshift-no-classic-resources"
	test.RunPassingExamplesTest(t, expectedCode)
}
