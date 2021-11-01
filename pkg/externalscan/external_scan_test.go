package externalscan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/defsec/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testContent = `---
Parameters:
  BucketName: 
    Type: String
    Default: naughty
  EncryptBucket:
    Type: Boolean
    Default: false
Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName:
        Ref: BucketName
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: true
        RestrictPublicBuckets: false
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: !Ref EncryptBucket
`

func TestExternal(t *testing.T) {

	tmp := os.TempDir()
	testDir := filepath.Join(tmp, fmt.Sprintf("cfsec-test-%d", time.Now().UnixNano()))

	err := os.MkdirAll(filepath.Join(testDir, "cf"), 0777)
	require.NoError(t, err)

	testFile := filepath.Join(testDir, "cf", "example.yaml")
	defer func() { _ = os.RemoveAll(testDir) }()

	err = os.WriteFile(testFile, []byte(testContent), 0777)
	require.NoError(t, err)

	scanner := NewExternalScanner()
	results, err := scanner.Scan(testFile)
	require.NoError(t, err)

	assert.Len(t, results, 9)

	var failedChecks int
	for _, result := range results {
		if result.Status == rules.StatusFailed {
			failedChecks += 1
		}
	}
	assert.Equal(t, 6, failedChecks)
}
