package elb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)

func CheckAlbNotPublic_FailureExamples(t *testing.T) {
	expectedCode := elb.CheckAlbNotPublic.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckAlbNotPublic_PassedExamples(t *testing.T) {
	expectedCode := elb.CheckAlbNotPublic.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
