package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_VPCSGRDescription_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group-rule"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPCSGRDescription_PassedExamples(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group-rule"
	test.RunPassingExamplesTest(t, expectedCode)
}
