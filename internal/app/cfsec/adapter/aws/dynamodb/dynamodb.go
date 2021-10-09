package dynamodb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) dynamodb.DynamoDB {

	return dynamodb.DynamoDB{
		DAXClusters: getClusters(cfFile),
	}
}
