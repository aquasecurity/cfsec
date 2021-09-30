package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

var (
	projectRoot, _ = os.Getwd()
	webPath        string
)

type FileContent struct {
	Checks   []rule.Rule
}

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

		fileContents := getSortedFileContents()

		return generateWebPages(fileContents)
	},
}

func getSortedFileContents() []rule.Rule {
	rules := scanner.GetRegisteredRules()
	sortChecks(rules)
	if err := generateNavIndexFile(rules); err != nil {
		panic(err)
	}
	return rules
}

func sortChecks(checks []rule.Rule) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].ID() < checks[j].ID()
	})
}
