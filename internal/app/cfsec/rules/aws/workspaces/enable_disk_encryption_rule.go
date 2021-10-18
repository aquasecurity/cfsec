package documentdb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/workspaces"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::WorkSpaces::Workspace
    Properties: 
      RootVolumeEncryptionEnabled: false
      UserVolumeEncryptionEnabled: false
      UserName: "admin"
`, `{
  "Resources": {
    "BadExample": {
      "Type": "AWS::WorkSpaces::Workspace",
      "Properties": {
        "RootVolumeEncryptionEnabled": false,
        "UserVolumeEncryptionEnabled": false,
        "UserName": "admin"
	  }
	}
  }
}`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserVolumeEncryptionEnabled: true
      UserName: "admin"
`,
			`{
		    "Resources": {
		      "GoodExample": {
		        "Type": "AWS::WorkSpaces::Workspace",
		        "Properties": {
		          "RootVolumeEncryptionEnabled": true,
		          "UserVolumeEncryptionEnabled": true,
		          "UserName": "admin"
		  	  }
		  	}
		    }
		  }`,
		},
		Base: workspaces.CheckEnableDiskEncryption,
	})
}
