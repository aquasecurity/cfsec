package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_VPC_NoPublicIngressSGR_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress-sgr"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPC_NoPublicIngressSGR_SuccessExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress-sgr"
	test.RunPassingExamplesTest(t, expectedCode)
}
