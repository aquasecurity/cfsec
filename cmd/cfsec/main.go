package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"

	"github.com/awslabs/goformation/v5"
)

func main() {

	if len(os.Args) < 2 {
		os.Args = append(os.Args, ".")
	}
	filepath := os.Args[1]

	template, err := goformation.Open(filepath)
	if err != nil {
		panic(err)
	}

	var resources resource.Resources

	for name, r := range template.Resources {
		formationType := r.AWSCloudFormationType()
		resources = append(resources, resource.NewCFResource(&r, formationType, string(name)))
	}

	s := scanner.New()
	results := s.Scan(resources)

	for _, r := range results {
		fmt.Println(r.Description)
	}

}
