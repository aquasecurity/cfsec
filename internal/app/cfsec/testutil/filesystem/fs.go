package filesystem

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FileSystem ...
type FileSystem struct {
	root string
}

// New ...
func New() (*FileSystem, error) {

	tempDir := os.TempDir()
	if runtime.GOOS == "darwin" {
		// osx tmpdir path is a symlink to /private/var/... which messes with tests
		osxTmpDir := os.TempDir()
		if strings.HasPrefix(osxTmpDir, "/var") {
			tempDir = filepath.Join("/private/", osxTmpDir)
		}
	}

	dir, err := ioutil.TempDir(tempDir, "tfsec")
	if err != nil {
		return nil, err
	}
	return &FileSystem{
		root: dir,
	}, nil
}

// RealPath ...
func (fs *FileSystem) RealPath(path string) string {
	return filepath.Join(fs.root, path)
}

// Close ...
func (fs *FileSystem) Close() error {
	return os.RemoveAll(fs.root)
}

// AddDir ...
func (fs *FileSystem) AddDir(path string) error {
	return os.MkdirAll(filepath.Join(fs.root, path), 0700)
}

// WriteFile ...
func (fs *FileSystem) WriteFile(path string, data []byte) error {
	if err := fs.AddDir(filepath.Dir(path)); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(fs.root, path), data, 0600)
}

// WriteTextFile ...
func (fs *FileSystem) WriteTextFile(path string, text string) error {
	return fs.WriteFile(path, []byte(text))
}
