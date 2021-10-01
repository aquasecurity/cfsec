package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_VPC_NoPublicIngressACL_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress-acl"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPC_NoPublicIngressACL_SuccessExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-public-ingress-acl"
	test.RunPassingExamplesTest(t, expectedCode)
}
