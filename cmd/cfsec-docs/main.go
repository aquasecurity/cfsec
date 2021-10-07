package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

var (
	projectRoot, _ = os.Getwd()
	webPath        string
)

func init() {
	defaultWebDocsPath := fmt.Sprintf("%s/checkdocs", projectRoot)
	rootCmd.Flags().StringVar(&webPath, "web-path", defaultWebDocsPath, "The path to generate web into, defaults to ./checkdocs")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cfsec-docs",
	Short: "cfsec-docs generates documentation for the checks in cfsec",
	Long:  `cfsec-docs generates the content for the root README and also can generate the missing base pages for the wiki`,
	RunE: func(cmd *cobra.Command, args []string) error {

		checks := getSortedChecks()
		return generateWebPages(checks)
	},
}

func getSortedChecks() []rules.Rule {
	checks := scanner.GetRegisteredRules()

	// sort the checks alpha
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID() < checks[j].ID()
	})

	if err := generateNavIndexFile(checks); err != nil {
		panic(err)
	}

	return checks
}
