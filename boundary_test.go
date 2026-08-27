package identity_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func sdkRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve SDK boundary test path")
	}
	return filepath.Dir(sourceFile)
}

func TestSDKRootContainsOnlyThePublicFacade(t *testing.T) {
	repositoryRoot := sdkRepositoryRoot(t)
	entries, err := os.ReadDir(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"sdk.go": true, "boundary_test.go": true, "external_api_test.go": true}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !allowed[entry.Name()] {
			t.Errorf("SDK root file %s bypasses business packages; keep only sdk.go as the public facade", entry.Name())
		}
	}
}

func TestBusinessContractsDoNotDependOnOuterAdapters(t *testing.T) {
	repositoryRoot := sdkRepositoryRoot(t)
	coreDirectories := []string{"authentication", "authorization", "identity"}
	forbidden := []string{
		"github.com/domainry/domainry-identity-sdk/application",
		"github.com/domainry/domainry-identity-sdk/browsergateway",
		"github.com/domainry/domainry-identity-sdk/contracttest",
		"github.com/domainry/domainry-identity-sdk/httpapi",
		"github.com/domainry/domainry-identity-sdk/httpmiddleware",
		"github.com/domainry/domainry-identity-sdk/remote",
	}
	for _, directory := range coreDirectories {
		err := filepath.WalkDir(filepath.Join(repositoryRoot, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				return nil
			}
			parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, declaration := range parsed.Imports {
				importPath, unquoteErr := strconv.Unquote(declaration.Path.Value)
				if unquoteErr != nil {
					return unquoteErr
				}
				for _, prefix := range forbidden {
					if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
						t.Errorf("business contract %s imports outer adapter %s", path, importPath)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBusinessImplementationsDoNotDependBackOnRootFacade(t *testing.T) {
	repositoryRoot := sdkRepositoryRoot(t)
	rootImport := "github.com/domainry/domainry-identity-sdk"
	for _, directory := range []string{"authentication", "authorization", "identity"} {
		err := filepath.WalkDir(filepath.Join(repositoryRoot, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, declaration := range parsed.Imports {
				importPath, unquoteErr := strconv.Unquote(declaration.Path.Value)
				if unquoteErr != nil {
					return unquoteErr
				}
				if importPath == rootImport {
					t.Errorf("business implementation %s depends back on the root facade", path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSDKContainsNoPersistenceContracts(t *testing.T) {
	repositoryRoot := sdkRepositoryRoot(t)
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, declaration := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(declaration.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if importPath == "database/sql" {
				t.Errorf("SDK file %s imports persistence capability %s", path, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSDKDoesNotDependOnIdentityImplementationOrPlane(t *testing.T) {
	repositoryRoot := sdkRepositoryRoot(t)
	forbidden := []string{
		"github.com/domainry/domainry-plane",
		"github.com/domainry/domainry-identity/internal",
	}
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, declaration := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(declaration.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			for _, prefix := range forbidden {
				if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
					t.Errorf("SDK file %s imports implementation package %s", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
