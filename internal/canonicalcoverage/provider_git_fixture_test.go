package canonicalcoverage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/domain/device"
	"github.com/ijonahch/codecomm/internal/domain/publication"
	"github.com/ijonahch/codecomm/internal/domain/voterset"
)

const (
	gitFixtureSessionID   = domain.UUIDv7("01890f47-3e72-7000-8000-000000000001")
	gitFixtureWorkspaceID = domain.UUIDv4("550e8400-e29b-41d4-a716-446655440000")
)

type gitFixtureProvider struct {
	gitPath      string
	repository   string
	workspaceID  domain.UUIDv4
	objectFormat domain.GitObjectFormat
	environment  []string

	mu    sync.Mutex
	calls []Subject
}

func (provider *gitFixtureProvider) capability() *Provider {
	return newProvider(provider.verifyAndIssue)
}

func (provider *gitFixtureProvider) verifyAndIssue(
	ctx context.Context,
	subject Subject,
	issue func() error,
) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls = append(provider.calls, subject)

	if subject.WorkspaceID != provider.workspaceID {
		return fmt.Errorf(
			"workspace %q does not own fixture repository %q",
			subject.WorkspaceID,
			provider.workspaceID,
		)
	}
	if subject.CommitOID.ObjectFormat() != provider.objectFormat {
		return fmt.Errorf(
			"object format %q does not match repository format %q",
			subject.CommitOID.ObjectFormat(),
			provider.objectFormat,
		)
	}
	if err := provider.verifyRepositoryPolicy(ctx); err != nil {
		return err
	}
	symbolicTarget, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"for-each-ref",
		"--format=%(symref)",
		publication.CanonicalRefName,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect canonical ref storage: %w%s",
			err,
			gitFixtureStderr(stderr),
		)
	}
	if strings.TrimSpace(symbolicTarget) != "" {
		return fmt.Errorf(
			"canonical ref is symbolic to %q",
			strings.TrimSpace(symbolicTarget),
		)
	}
	refOID, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"show-ref",
		"--verify",
		"--hash",
		publication.CanonicalRefName,
	)
	if err != nil {
		return fmt.Errorf(
			"verify canonical ref: %w%s",
			err,
			gitFixtureStderr(stderr),
		)
	}
	if strings.TrimSpace(refOID) != subject.CommitOID.Hex() {
		return fmt.Errorf(
			"canonical ref names %q, want %q",
			strings.TrimSpace(refOID),
			subject.CommitOID.Hex(),
		)
	}
	stdout, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"cat-file",
		"-t",
		subject.CommitOID.Hex(),
	)
	if err != nil {
		return fmt.Errorf(
			"inspect canonical object %s: %w%s",
			subject.CommitOID,
			err,
			gitFixtureStderr(stderr),
		)
	}
	if objectType := strings.TrimSpace(stdout); objectType != "commit" {
		return fmt.Errorf(
			"canonical object %s has type %q, want commit",
			subject.CommitOID,
			objectType,
		)
	}
	content, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"cat-file",
		"commit",
		subject.CommitOID.Hex(),
	)
	if err != nil {
		return fmt.Errorf(
			"read canonical commit %s: %w%s",
			subject.CommitOID,
			err,
			gitFixtureStderr(stderr),
		)
	}
	recomputed, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		content,
		"-C",
		provider.repository,
		"hash-object",
		"-t",
		"commit",
		"--stdin",
	)
	if err != nil {
		return fmt.Errorf(
			"hash canonical commit %s: %w%s",
			subject.CommitOID,
			err,
			gitFixtureStderr(stderr),
		)
	}
	if strings.TrimSpace(recomputed) != subject.CommitOID.Hex() {
		return fmt.Errorf(
			"canonical commit content hashes to %q, want %q",
			strings.TrimSpace(recomputed),
			subject.CommitOID.Hex(),
		)
	}
	_, stderr, err = runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"fsck",
		"--strict",
		"--no-dangling",
		"--no-reflogs",
		subject.CommitOID.Hex(),
	)
	if err != nil {
		return fmt.Errorf(
			"verify canonical closure %s: %w%s",
			subject.CommitOID,
			err,
			gitFixtureStderr(stderr),
		)
	}
	return issue()
}

func (provider *gitFixtureProvider) verifyRepositoryPolicy(
	ctx context.Context,
) error {
	alternatesPath := filepath.Join(
		provider.repository,
		".git",
		"objects",
		"info",
		"alternates",
	)
	if _, err := os.Lstat(alternatesPath); err == nil {
		return errors.New("repository alternates are forbidden")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect repository alternates: %w", err)
	}
	shallow, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"rev-parse",
		"--is-shallow-repository",
	)
	if err != nil {
		return fmt.Errorf(
			"inspect shallow repository state: %w%s",
			err,
			gitFixtureStderr(stderr),
		)
	}
	if strings.TrimSpace(shallow) != "false" {
		return errors.New("shallow repositories are forbidden")
	}
	partial, stderr, err := runGitFixtureCommand(
		ctx,
		provider.gitPath,
		provider.environment,
		"",
		"-C",
		provider.repository,
		"config",
		"--local",
		"--get-regexp",
		`^(extensions\.partialClone|remote\..*\.promisor)$`,
	)
	if err == nil {
		return fmt.Errorf(
			"promisor/partial-clone configuration is forbidden: %s",
			strings.TrimSpace(partial),
		)
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		return fmt.Errorf(
			"inspect promisor configuration: %w%s",
			err,
			gitFixtureStderr(stderr),
		)
	}
	return nil
}

func (provider *gitFixtureProvider) recordedCalls() []Subject {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]Subject(nil), provider.calls...)
}

type gitFixtureRepository struct {
	path            string
	format          domain.GitObjectFormat
	commitOID       domain.GitOID
	alternateCommit domain.GitOID
	parentCommit    domain.GitOID
	presentBlob     domain.GitOID
	presentTree     domain.GitOID
}

func TestGitFixtureProviderSignsOnlyVerifiedCommitObjects(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("system Git is unavailable: %v", err)
	}

	t.Run("sha1", func(t *testing.T) {
		repository, supported := newGitFixtureRepository(
			t,
			gitPath,
			domain.GitObjectSHA1,
		)
		if !supported {
			t.Fatal("SHA-1 repository unexpectedly unsupported")
		}
		testGitFixtureProvider(t, gitPath, repository)
	})

	t.Run("sha256", func(t *testing.T) {
		repository, supported := newGitFixtureRepository(
			t,
			gitPath,
			domain.GitObjectSHA256,
		)
		if !supported {
			t.Fatal("installed Git does not support SHA-256 repositories")
		}
		testGitFixtureProvider(t, gitPath, repository)
	})
}

func testGitFixtureProvider(
	t *testing.T,
	gitPath string,
	repository gitFixtureRepository,
) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signer identity: %v", err)
	}
	voterDeviceID, err := device.DeriveID(publicKey)
	if err != nil {
		t.Fatalf("derive signer device ID: %v", err)
	}
	voterSet, err := voterset.New(
		gitFixtureSessionID,
		[]domain.DeviceID{voterDeviceID},
		1,
	)
	if err != nil {
		t.Fatalf("construct voter set: %v", err)
	}
	provider := &gitFixtureProvider{
		gitPath:      gitPath,
		repository:   repository.path,
		workspaceID:  gitFixtureWorkspaceID,
		objectFormat: repository.format,
		environment:  gitFixtureEnvironment(),
	}
	providerCapability := provider.capability()

	requirementFor := func(oid domain.GitOID) Requirement {
		return Requirement{
			SessionID:   gitFixtureSessionID,
			WorkspaceID: gitFixtureWorkspaceID,
			VoterSet:    voterSet,
			CanonicalRef: publication.CanonicalRef{
				RefName:       publication.CanonicalRefName,
				CommitOID:     oid,
				EntityVersion: 1,
			},
		}
	}
	signRequirement := func(
		testingT *testing.T,
		requirement Requirement,
	) (Receipt, error) {
		testingT.Helper()
		before := len(provider.recordedCalls())
		snapshot, snapshotErr := NewSnapshot(
			requirement,
			map[domain.DeviceID]ed25519.PublicKey{
				voterDeviceID: publicKey,
			},
		)
		if snapshotErr != nil {
			testingT.Fatalf("NewSnapshot(): %v", snapshotErr)
		}
		signer, signerErr := NewSigner(
			providerCapability,
			snapshot,
			voterDeviceID,
			privateKey,
		)
		if signerErr != nil {
			testingT.Fatalf("NewSigner(): %v", signerErr)
		}
		defer signer.Close()
		receipt, signErr := signer.Sign(context.Background())
		calls := provider.recordedCalls()
		if len(calls) != before+1 {
			testingT.Fatalf(
				"provider calls after Sign() = %d, want %d",
				len(calls),
				before+1,
			)
		}
		if got := calls[len(calls)-1].CommitOID; got !=
			requirement.CanonicalRef.CommitOID {
			testingT.Fatalf(
				"provider inspected OID %q, want %q",
				got,
				requirement.CanonicalRef.CommitOID,
			)
		}
		return receipt, signErr
	}
	sign := func(testingT *testing.T, oid domain.GitOID) (Receipt, error) {
		testingT.Helper()
		return signRequirement(testingT, requirementFor(oid))
	}
	setCanonicalRef := func(oid domain.GitOID) {
		t.Helper()
		mustRunGitFixture(
			t,
			gitPath,
			provider.environment,
			"",
			"-C",
			repository.path,
			"update-ref",
			publication.CanonicalRefName,
			oid.Hex(),
		)
	}
	expectDegraded := func(name string, oid domain.GitOID) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, signErr := sign(t, oid); !errors.Is(
				signErr,
				ErrObjectCoverageDegraded,
			) {
				t.Fatalf(
					"Sign() error = %v, want ErrObjectCoverageDegraded",
					signErr,
				)
			}
		})
	}

	for attempt := 1; attempt <= 2; attempt++ {
		receipt, signErr := sign(t, repository.commitOID)
		if signErr != nil {
			t.Fatalf("exact commit Sign() attempt %d error = %v", attempt, signErr)
		}
		if got := receipt.Subject().CommitOID; got != repository.commitOID {
			t.Fatalf("receipt commit OID = %q, want %q", got, repository.commitOID)
		}
		if verifyErr := receipt.Verify(publicKey); verifyErr != nil {
			t.Fatalf("receipt Verify() attempt %d error = %v", attempt, verifyErr)
		}
	}

	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"update-ref",
		"refs/codecomm/symbolic-target",
		repository.commitOID.Hex(),
	)
	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"symbolic-ref",
		publication.CanonicalRefName,
		"refs/codecomm/symbolic-target",
	)
	expectDegraded("symbolic canonical ref", repository.commitOID)
	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"symbolic-ref",
		"--delete",
		publication.CanonicalRefName,
	)
	setCanonicalRef(repository.commitOID)

	alternatesPath := filepath.Join(
		repository.path,
		".git",
		"objects",
		"info",
		"alternates",
	)
	if err := os.WriteFile(
		alternatesPath,
		[]byte(filepath.Join(t.TempDir(), "objects")+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write alternates control: %v", err)
	}
	expectDegraded("repository alternates", repository.commitOID)
	if err := os.Remove(alternatesPath); err != nil {
		t.Fatalf("remove alternates control: %v", err)
	}

	shallowPath := filepath.Join(repository.path, ".git", "shallow")
	if err := os.WriteFile(
		shallowPath,
		[]byte(repository.parentCommit.Hex()+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write shallow control: %v", err)
	}
	expectDegraded("shallow repository", repository.commitOID)
	if err := os.Remove(shallowPath); err != nil {
		t.Fatalf("remove shallow control: %v", err)
	}

	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"config",
		"--local",
		"remote.fixture.promisor",
		"true",
	)
	expectDegraded("promisor repository", repository.commitOID)
	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"config",
		"--local",
		"--unset",
		"remote.fixture.promisor",
	)

	setCanonicalRef(repository.alternateCommit)
	expectDegraded("moved canonical ref", repository.commitOID)
	setCanonicalRef(repository.commitOID)

	mustRunGitFixture(
		t,
		gitPath,
		provider.environment,
		"",
		"-C",
		repository.path,
		"update-ref",
		"-d",
		publication.CanonicalRefName,
		repository.commitOID.Hex(),
	)
	expectDegraded("deleted canonical ref", repository.commitOID)
	setCanonicalRef(repository.commitOID)

	setCanonicalRef(repository.presentBlob)
	expectDegraded("present blob", repository.presentBlob)
	setCanonicalRef(repository.presentTree)
	expectDegraded("present tree", repository.presentTree)
	setCanonicalRef(repository.commitOID)

	for _, test := range []struct {
		name string
		oid  domain.GitOID
	}{
		{"missing parent commit", repository.parentCommit},
		{"missing root tree", repository.presentTree},
		{"missing reachable blob", repository.presentBlob},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := gitFixtureLooseObjectPath(repository.path, test.oid)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture object %s: %v", test.oid, err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat fixture object %s: %v", test.oid, err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove fixture object %s: %v", test.oid, err)
			}
			defer func() {
				if err := os.WriteFile(
					path,
					content,
					info.Mode().Perm(),
				); err != nil {
					t.Errorf("restore fixture object %s: %v", test.oid, err)
				}
			}()
			_, signErr := sign(t, repository.commitOID)
			if !errors.Is(signErr, ErrObjectCoverageDegraded) {
				t.Fatalf(
					"Sign() error = %v, want ErrObjectCoverageDegraded",
					signErr,
				)
			}
		})
	}

	wrongWorkspace := requirementFor(repository.commitOID)
	wrongWorkspace.WorkspaceID =
		domain.UUIDv4("550e8400-e29b-41d4-a716-446655440001")
	if _, signErr := signRequirement(t, wrongWorkspace); !errors.Is(
		signErr,
		ErrObjectCoverageDegraded,
	) {
		t.Fatalf(
			"wrong-workspace Sign() error = %v, want ErrObjectCoverageDegraded",
			signErr,
		)
	}

	wrongFormat := domain.GitObjectSHA256
	wrongLength := 64
	if repository.format == domain.GitObjectSHA256 {
		wrongFormat = domain.GitObjectSHA1
		wrongLength = 40
	}
	wrongOID, err := domain.ParseGitOID(
		string(wrongFormat) + ":" + strings.Repeat("f", wrongLength),
	)
	if err != nil {
		t.Fatalf("ParseGitOID(wrong format): %v", err)
	}
	expectDegraded("wrong object format", wrongOID)

	objectPath := gitFixtureLooseObjectPath(
		repository.path,
		repository.commitOID,
	)
	if err := os.Chmod(objectPath, 0o600); err != nil {
		t.Fatalf("make fixture commit writable: %v", err)
	}
	if err := os.WriteFile(objectPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt fixture commit: %v", err)
	}
	expectDegraded("corrupt commit object", repository.commitOID)
}

func newGitFixtureRepository(
	t *testing.T,
	gitPath string,
	format domain.GitObjectFormat,
) (gitFixtureRepository, bool) {
	t.Helper()

	repositoryPath := filepath.Join(t.TempDir(), "repository")
	initArguments := []string{"init", "--quiet"}
	if format == domain.GitObjectSHA256 {
		initArguments = append(initArguments, "--object-format=sha256")
	}
	initArguments = append(initArguments, repositoryPath)
	environment := gitFixtureEnvironment()
	_, stderr, err := runGitFixtureCommand(
		context.Background(),
		gitPath,
		environment,
		"",
		initArguments...,
	)
	if err != nil {
		if format == domain.GitObjectSHA256 {
			t.Logf(
				"SHA-256 repository initialization unavailable: %v%s",
				err,
				gitFixtureStderr(stderr),
			)
			return gitFixtureRepository{}, false
		}
		t.Fatalf(
			"initialize %s fixture repository: %v%s",
			format,
			err,
			gitFixtureStderr(stderr),
		)
	}

	blobHex := mustRunGitFixture(
		t,
		gitPath,
		environment,
		"CodeComm canonical coverage fixture\n",
		"-C",
		repositoryPath,
		"hash-object",
		"-w",
		"--stdin",
	)
	treeHex := mustRunGitFixture(
		t,
		gitPath,
		environment,
		fmt.Sprintf("100644 blob %s\tcanonical.txt\n", blobHex),
		"-C",
		repositoryPath,
		"mktree",
	)
	commitEnvironment := append(
		append([]string(nil), environment...),
		"GIT_AUTHOR_NAME=CodeComm Fixture",
		"GIT_AUTHOR_EMAIL=fixture@codecomm.invalid",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z",
		"GIT_COMMITTER_NAME=CodeComm Fixture",
		"GIT_COMMITTER_EMAIL=fixture@codecomm.invalid",
		"GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	parentCommitHex := mustRunGitFixture(
		t,
		gitPath,
		commitEnvironment,
		"CodeComm canonical coverage parent\n",
		"-C",
		repositoryPath,
		"-c",
		"commit.gpgSign=false",
		"commit-tree",
		treeHex,
		"-F",
		"-",
	)
	commitHex := mustRunGitFixture(
		t,
		gitPath,
		commitEnvironment,
		"CodeComm canonical coverage fixture\n",
		"-C",
		repositoryPath,
		"-c",
		"commit.gpgSign=false",
		"commit-tree",
		treeHex,
		"-p",
		parentCommitHex,
		"-F",
		"-",
	)
	alternateCommitHex := mustRunGitFixture(
		t,
		gitPath,
		commitEnvironment,
		"CodeComm alternate canonical coverage fixture\n",
		"-C",
		repositoryPath,
		"-c",
		"commit.gpgSign=false",
		"commit-tree",
		treeHex,
		"-F",
		"-",
	)
	mustRunGitFixture(
		t,
		gitPath,
		environment,
		"",
		"-C",
		repositoryPath,
		"update-ref",
		publication.CanonicalRefName,
		commitHex,
	)

	return gitFixtureRepository{
		path:            repositoryPath,
		format:          format,
		commitOID:       parseGitFixtureOID(t, format, commitHex),
		alternateCommit: parseGitFixtureOID(t, format, alternateCommitHex),
		parentCommit:    parseGitFixtureOID(t, format, parentCommitHex),
		presentBlob:     parseGitFixtureOID(t, format, blobHex),
		presentTree:     parseGitFixtureOID(t, format, treeHex),
	}, true
}

func parseGitFixtureOID(
	t *testing.T,
	format domain.GitObjectFormat,
	hex string,
) domain.GitOID {
	t.Helper()
	oid, err := domain.ParseGitOID(string(format) + ":" + hex)
	if err != nil {
		t.Fatalf("parse %s fixture OID %q: %v", format, hex, err)
	}
	return oid
}

func gitFixtureLooseObjectPath(
	repositoryPath string,
	oid domain.GitOID,
) string {
	hex := oid.Hex()
	return filepath.Join(
		repositoryPath,
		".git",
		"objects",
		hex[:2],
		hex[2:],
	)
}

func mustRunGitFixture(
	t *testing.T,
	gitPath string,
	environment []string,
	stdin string,
	arguments ...string,
) string {
	t.Helper()
	stdout, stderr, err := runGitFixtureCommand(
		context.Background(),
		gitPath,
		environment,
		stdin,
		arguments...,
	)
	if err != nil {
		t.Fatalf(
			"git %q failed: %v%s",
			arguments,
			err,
			gitFixtureStderr(stderr),
		)
	}
	return strings.TrimSpace(stdout)
}

func runGitFixtureCommand(
	ctx context.Context,
	gitPath string,
	environment []string,
	stdin string,
	arguments ...string,
) (string, string, error) {
	command := exec.CommandContext(ctx, gitPath, arguments...)
	command.Env = environment
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func gitFixtureEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(strings.ToUpper(name), "GIT_") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(
		environment,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1",
	)
}

func gitFixtureStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
