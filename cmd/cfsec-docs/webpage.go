package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
)

const (
	baseWebPageTemplate = `---
title: {{$.Summary}}
shortcode: {{$.ShortCode}}
summary: {{$.Summary}} 
permalink: /docs/{{$.Service}}/{{$.ShortCode}}/
---

### Explanation

{{$.Explanation}}

### Possible Impact
{{$.Impact}}

### Suggested Resolution
{{$.Resolution}}

{{if $.BadExample }}
### Insecure Example

The following example will fail the {{$.ID}} check.

` + "```yaml" + `
{{ (index $.BadExample 0) }}
` + "```" + `

{{end}}
{{if $.GoodExample }}
### Secure Example

The following example will pass the {{$.ID}} check.

` + "```yaml" + `
{{ (index $.GoodExample 0) }}
` + "```" + `

{{end}}

{{if $.Links}}
### Related Links

{{range $link := $.Links}}
- [{{.}}]({{.}})
{{end}}
{{end}}
`
)

type docEntry struct {
	Summary     string
	ID          string
	ShortCode   string
	Service     string
	Explanation string
	Impact      string
	Resolution  string
	BadExample  []string
	GoodExample []string
	Links       []string
}

func newEntry(check rules.Rule) docEntry {

	var links []string
	for _, link := range check.Base.Rule().Links {
		if strings.HasPrefix(link, "https://cfsec.dev") {
			continue
		}
		links = append(links, link)
	}

	return docEntry{
		Summary:     check.Base.Rule().Summary,
		ID:          check.ID(),
		ShortCode:   check.Base.Rule().ShortCode,
		Explanation: check.Base.Rule().Explanation,
		Impact:      check.Base.Rule().Impact,
		Resolution:  check.Base.Rule().Resolution,
		BadExample:  check.BadExample,
		GoodExample: check.GoodExample,
		Service:     check.Base.Rule().Service,
		Links:       links,
	}
}

func generateWebPages(fileContents []rules.Rule) error {
	for _, check := range fileContents {
		webProviderPath := fmt.Sprintf("docs/checks/%s", strings.ToLower(check.Base.Rule().Service))
		entry := newEntry(check)
		if err := generateWebPage(webProviderPath, entry); err != nil {
			return err
		}
	}
	return nil
}

var funcMap = template.FuncMap{
	"ToUpper": strings.ToUpper,
	"Join":    join,
}

func join(s []string) string {
	if s == nil {
		return ""
	}
	return strings.Join(s[1:], s[0])
}

func generateWebPage(webProviderPath string, r docEntry) error {

	if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
		return err
	}
	filePath := fmt.Sprintf("%s/%s.md", webProviderPath, r.ShortCode)
	fmt.Printf("Generating page for %s at %s\n", r.ID, filePath)
	webTmpl := template.Must(template.New("web").Funcs(funcMap).Parse(baseWebPageTemplate))

	return writeTemplate(r, filePath, webTmpl)

}

func writeTemplate(contents interface{}, path string, tmpl *template.Template) error {
	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = outputFile.Close() }()
	return tmpl.Execute(outputFile, contents)
}
