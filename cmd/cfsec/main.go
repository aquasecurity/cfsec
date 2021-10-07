package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/formatters"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func main() {

	if len(os.Args) < 2 {
		if wd, err := os.Getwd(); err != nil {
			os.Args = append(os.Args, wd)
		}
	}
	filepath := os.Args[1]

	var contexts parser.FileContexts
	var err error

	if stat, err := os.Stat(filepath); err == nil {
		if stat.IsDir() {
			contexts, err = parser.ParseDirectory(filepath)
		} else {
			contexts, err = parser.ParseFiles(filepath)
		}
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else {
		panic(fmt.Errorf("couldn't find the filepath when stating"))
	}

	if err != nil {
		panic(err)
	}
	s := scanner.New()
	results := s.Scan(contexts)

	formatters.FormatDefault(os.Stdout, results, "")
}
