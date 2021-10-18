package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/formatters"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/liamg/tml"
	"github.com/spf13/cobra"
)

var disableColours = false
var format string
var parameters string

func init() {
	rootCmd.Flags().BoolVar(&debug.Enabled, "verbose", debug.Enabled, "Enable verbose logging")
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv")
	rootCmd.Flags().StringVarP(&parameters, "parameters", "p", parameters, "Pass comma separated parameter values. eg; Key1=Value1,Key2=Value2")
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cfsec [directory]",
	Short: "cfsec scans your Cloudformation configuration",
	Long:  "Use cfsec to scan your yaml of json Cloudformation configurations for common security misconfigurations",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		// disable colour if running on Windows - colour formatting doesn't work
		if disableColours || runtime.GOOS == "windows" {
			debug.Log("Disabled colour formatting")
			tml.DisableFormatting()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var dir string
		var err error

		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var contexts parser.FileContexts
		p := parser.NewParser(getOptions()...)

		if stat, err := os.Stat(dir); err == nil {
			if stat.IsDir() {
				contexts, err = p.ParseDirectory(dir)
			} else {
				contexts, err = p.ParseFiles(dir)
			}
			if err != nil {
				return err
			}
		} else {
			panic(fmt.Errorf("couldn't find the filepath when stating"))
		}

		if err != nil {
			panic(err)
		}
		s := scanner.New()
		results := s.Scan(contexts)

		formatter, err := getFormatter()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		return formatter(os.Stdout, results, "")
	},
}

func getOptions() []parser.Option {
	var options []parser.Option
	if len(parameters) > 0 {
		options = append(options, parser.ProvidedParametersOption(parameters))
	}
	return options
}

func getFormatter() (formatters.Formatter, error) {
	switch strings.ToLower(format) {
	case "", "default":
		return formatters.FormatDefault, nil
	case "json":
		return formatters.FormatJSON, nil
	case "csv":
		return formatters.FormatCSV, nil
	default:
		return nil, fmt.Errorf("invalid format specified: '%s'", format)
	}
}
