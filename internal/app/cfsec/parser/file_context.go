package parser

type FileContexts []FileContext

type FileContext struct {
	filepath   string
	Parameters map[string]*Parameter `json:"Parameters" yaml:"Parameters"`
	Resources  map[string]*Resource  `json:"Resources" yaml:"Resources"`
}

func newFileContext(filepath string) FileContext {
	return FileContext{
		filepath: filepath,
	}
}

func (t *FileContext) GetResourceByName(name string) *Resource {
	for n, r := range t.Resources {
		if name == n {
			return r
		}
	}
	return nil
}

func (t *FileContext) GetResourceByType(name string) []*Resource {
	var resources []*Resource
	for _, r := range t.Resources {
		if name == r.Type() {
			resources = append(resources, r)
		}
	}
	return resources
}
