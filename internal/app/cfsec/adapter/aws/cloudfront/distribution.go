package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/types"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourceByType("AWS::CloudFront::Distribution")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			WAFID: getWafId(r, ctx),
			Logging: cloudfront.Logging{
				Bucket: getBucketName(r, ctx),
			},
			DefaultCacheBehaviour:  getDefaultCacheBehaviour(r, ctx),
			OrdererCacheBehaviours: nil,
			ViewerCertificate: cloudfront.ViewerCertificate{
				MinimumProtocolVersion: getTlsVersion(r),
			},
		}

		distributions = append(distributions, distribution)
	}

	return distributions
}

func getDefaultCacheBehaviour(r *parser.Resource, ctx parser.FileContext) cloudfront.CacheBehaviour {
	defaultCache := r.GetProperty("DistributionConfig.DefaultCacheBehavior")
	if defaultCache.IsNil() {
		return cloudfront.CacheBehaviour{
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}
	protoProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy")
	if protoProp.IsNil() {
		return cloudfront.CacheBehaviour{
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}

	return cloudfront.CacheBehaviour{
		ViewerProtocolPolicy: protoProp.AsStringValue(),
	}
}

func getTlsVersion(r *parser.Resource) types.StringValue {

	tlsVerProp := r.GetProperty("DistributionConfig.ViewerCertificate.MinimumProtocolVersion")

	if tlsVerProp.IsNil() {
		return types.StringDefault("TLSv1", r.Metadata())
	}

	if tlsVerProp.IsEmpty() {
		return types.StringDefault("TLSv1", r.Metadata())
	}

	return tlsVerProp.AsStringValue()
}

func getBucketName(r *parser.Resource, ctx parser.FileContext) types.StringValue {
	logBucketProp := r.GetProperty("DistributionConfig.Logging.Bucket")
	if logBucketProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}
	if logBucketProp.IsEmpty() {
		return types.StringDefault("", logBucketProp.Metadata())
	}
	return logBucketProp.AsStringValue()
}

func getWafId(r *parser.Resource, ctx parser.FileContext) types.StringValue {
	wafIdProp := r.GetProperty("DistributionConfig.WebACLId")
	if wafIdProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}
	if wafIdProp.IsEmpty() {
		return types.StringDefault("", wafIdProp.Metadata())
	}
	return wafIdProp.AsStringValue()
}
