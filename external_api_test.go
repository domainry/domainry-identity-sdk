package identity_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExternalConsumerCompilesEveryPublicGoPackage(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve SDK repository path")
	}
	repository := filepath.Dir(sourceFile)
	foundationRepository := filepath.Join(filepath.Dir(repository), "domainry-foundation")
	if _, err := os.Stat(filepath.Join(foundationRepository, "modulecapability", "contract.go")); err != nil {
		t.Fatalf("resolve Foundation repository used by the current SDK contract: %v", err)
	}
	consumer := t.TempDir()
	goMod := "module example.com/identity-consumer\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/domainry/domainry-foundation v0.0.0\n\tgithub.com/domainry/domainry-identity-sdk v0.0.0\n)\n\nreplace github.com/domainry/domainry-foundation => " + foundationRepository + "\n\nreplace github.com/domainry/domainry-identity-sdk => " + repository + "\n"
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	source := `package consumer

import (
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/application"
	"github.com/domainry/domainry-identity-sdk/authentication"
	"github.com/domainry/domainry-identity-sdk/authorization"
	"github.com/domainry/domainry-identity-sdk/authorization/evaluator"
	"github.com/domainry/domainry-identity-sdk/authorization/principal"
	"github.com/domainry/domainry-identity-sdk/browsergateway"
		_ "github.com/domainry/domainry-identity-sdk/contracttest"
		"github.com/domainry/domainry-identity-sdk/httpapi"
		"github.com/domainry/domainry-identity-sdk/httpmiddleware"
		identitymodel "github.com/domainry/domainry-identity-sdk/identity"
	"github.com/domainry/domainry-identity-sdk/remote"
)

var (
	_ identity.Factory
	_ identity.ProjectRoleCatalogPublisher
	_ identity.EmbeddedWorkspaceProvisioner
	_ authentication.Authentication
	_ authorization.Authorization
	_ identitymodel.Directory
		_ httpapi.Surface
	_ = application.Bind
	_ = evaluator.Evaluate
	_ = principal.NewResolver
	_ = browsergateway.New
	_ = httpmiddleware.New
	_ = remote.NewFactory
)
`
	if err := os.WriteFile(filepath.Join(consumer, "consumer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "./...")
	command.Dir = consumer
	command.Env = append(os.Environ(), "GOWORK=off", "GOSUMDB=off", "GOFLAGS=-mod=mod")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("external consumer compile: %v\n%s", err, output)
	}
}
