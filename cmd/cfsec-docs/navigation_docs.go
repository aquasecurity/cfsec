package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"gopkg.in/yaml.v2"
)

const navDocsTemplate = `---
- title: Getting Started
  state: open
  docs:
  - installation
  - usage

||CHECKBLOCK||

`

type navBlock struct {
	Title    string    `yaml:"title"`
	Services []service `yaml:"services"`
}

type service struct {
	Title   string   `yaml:"title"`
	Service string   `yaml:"service"`
	Docs    []string `yaml:"docs"`
}

func generateNavIndexFile(registeredChecks []rules.Rule) error {

	topLevel := &[]navBlock{
		{
			Title:    "Services",
			Services: getServices(registeredChecks),
		},
	}

	content, err := yaml.Marshal(topLevel)
	if err != nil {
		panic(err)
	}
	providerFilePath := fmt.Sprintf("%s/data/navigation_docs.yml", webPath)
	if err := os.MkdirAll(filepath.Dir(providerFilePath), os.ModePerm); err != nil {
		return err
	}

	navDocs := strings.ReplaceAll(navDocsTemplate, "||CHECKBLOCK||", string(content))

	file, err := os.Create(providerFilePath)
	if err != nil {
		panic(err)
	}

	_, err = file.Write([]byte(navDocs))
	return err
}

func getServices(checks []rules.Rule) []service {

	serviceMap := make(map[string][]string)

	for _, check := range checks {
		rulePath := fmt.Sprintf("%s/%s", check.Base.Rule().Service, check.Base.Rule().ShortCode)
		serviceMap[check.Base.Rule().Service] = append(serviceMap[check.Base.Rule().Service], rulePath)
	}

	var services []service

	for s, docs := range serviceMap {
		sort.Slice(docs, func(i, j int) bool {
			return docs[i] < docs[j]
		})
		services = append(services, service{
			Title:   s,
			Service: s,
			Docs:    docs,
		})
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Title < services[j].Title
	})

	return services

}
