package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_VPC_NoPublicEgressSGR_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-egress-sgr"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPC_NoPublicEgressSGR_SuccessExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-egress-sgr"
	test.RunPassingExamplesTest(t, expectedCode)
}
