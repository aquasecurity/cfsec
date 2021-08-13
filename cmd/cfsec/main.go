package main

import (
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/formatters"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func main() {

	if len(os.Args) < 2 {
		os.Args = append(os.Args, ".")
	}
	filepath := os.Args[1]

	resources, err := parser.New(filepath)
	if err != nil {
		panic(err)
	}
	s := scanner.New()
	results := s.Scan(resources)

	formatters.FormatDefault(os.Stdout, results, "")

}
