package elasticsearch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourceByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {
		
		domain := elasticsearch.Domain{
			Metadata:          r.Metadata(),
			DomainName:        r.GetStringProperty("DomainName", ""),
			LogPublishing:     elasticsearch.LogPublishing{
				AuditEnabled: r.GetBoolProperty("LogPublishingOptions.Enabled", false),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Enabled: r.GetBoolProperty("NodeToNodeEncryptionOptions.Enabled", false),
			},
			AtRestEncryption:  elasticsearch.AtRestEncryption{
				Enabled: r.GetBoolProperty("EncryptionAtRestOptions.Enabled", false),
			},
			Endpoint:          elasticsearch.Endpoint{
				EnforceHTTPS: r.GetBoolProperty("DomainEndpointOptions.EnforceHTTPS", false),
				TLSPolicy:    r.GetStringProperty("DomainEndpointOptions.TLSSecurityPolicy", "" ),
			},
		}

		domains = append(domains, domain)
	}

	return domains
}
