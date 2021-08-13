package resource

type Resources []Resource

func (resources Resources) OfType(t string) Resources {
	var results []Resource
	for _, resource := range resources {
		if resource.Type() == t {
			results = append(results, resource)
		}
	}
	return results
}
