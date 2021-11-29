---
title: Config configuration aggregator should be using all regions for source
shortcode: aggregate-all-regions
summary: Config configuration aggregator should be using all regions for source 
permalink: /docs/config/aggregate-all-regions/
---

### Explanation

The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.

### Possible Impact
Sources that aren't covered by the aggregator are not include in the configuration

### Suggested Resolution
Set the aggregator to cover all regions


### Insecure Example

The following example will fail the AVD-AWS-0019 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: "BadAccountLevelAggregation"

```



### Secure Example

The following example will pass the AVD-AWS-0019 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"

```




### Related Links


- [https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html)


