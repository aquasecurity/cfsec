package elasticache

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
)

func Test_CheckAddDescriptionForSecurityGroup_FailureExamples(t *testing.T) {
	expectedCode := elasticache.CheckAddDescriptionForSecurityGroup.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckAddDescriptionForSecurityGroup_PassedExamples(t *testing.T) {
	expectedCode := elasticache.CheckAddDescriptionForSecurityGroup.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
