package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
)

type checkBlock struct {
	Code        string `json:"code"`
	Service     string `json:"service"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Resolution  string `json:"resolution"`
	DocUrl      string `json:"doc_url"`
}

type checksBlock struct {
	Checks []checkBlock `json:"checks"`
}

func generateExtensionCodeFile(registeredChecks []rules.Rule) error {
	var blocks []checkBlock

	for _, check := range registeredChecks {
		blocks = append(blocks, checkBlock{
			Code:        check.ID(),
			Service:     check.Base.Rule().Service,
			Description: check.Base.Rule().Summary,
			Impact:      check.Base.Rule().Impact,
			Resolution:  check.Base.Rule().Resolution,
			DocUrl:      fmt.Sprintf("https://cfsec.dev/docs/%s/%s/", check.Base.Rule().Service, check.Base.Rule().ShortCode),
		})
	}

	file, err := os.Create("checkdocs/codes.json")
	if err != nil {
		panic(err)
	}

	out, err := json.MarshalIndent(checksBlock{
		Checks: blocks,
	}, "", " ")
	if err != nil {
		panic(err)
	}

	_, err = file.Write(out)

	return err
}
