package elasticsearch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elasticsearch.Elasticsearch {

	return elasticsearch.Elasticsearch{
		Domains: getDomains(cfFile),
	}

}
