package documentdb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {

	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}

}
