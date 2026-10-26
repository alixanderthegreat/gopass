package age

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// writeSSHKey writes an unencrypted ed25519 key pair to dir as name and name.pub, and returns the
// public key as an authorized_keys line, comment included.
func writeSSHKey(t *testing.T, dir, name string) string {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	line := string(ssh.MarshalAuthorizedKey(sshPub))
	line = line[:len(line)-1] + " test@host"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".pub"), []byte(line+"\n"), 0o644))

	return line
}

func resetSSHCache(t *testing.T) {
	t.Helper()

	sshCacheMu.Lock()
	sshCache = nil
	sshCacheMu.Unlock()
	t.Cleanup(func() {
		sshCacheMu.Lock()
		sshCache = nil
		sshCacheMu.Unlock()
	})
}

// A store whose only recipient is an SSH key can be initialized: FindIdentities, the check init
// runs, finds the key named by age.ssh-key-path - matching the authorized_keys line with its
// comment. A context that asks for native identities only still doesn't count it.
func TestFindIdentitiesSSHKeyPath(t *testing.T) {
	td := t.TempDir()
	t.Setenv("GOPASS_HOMEDIR", td)
	t.Setenv("GOPASS_SSH_DIR", "")
	resetSSHCache(t)

	keyDir := filepath.Join(td, "keys")
	require.NoError(t, os.MkdirAll(keyDir, 0o700))
	line := writeSSHKey(t, keyDir, "id_ed25519")
	other := writeSSHKey(t, t.TempDir(), "id_other")

	a, err := New(t.Context(), false, filepath.Join(keyDir, "id_ed25519.pub"))
	require.NoError(t, err)
	a.identity = filepath.Join(td, "no-identities")

	found, err := a.FindIdentities(t.Context(), line, other)
	require.NoError(t, err)
	assert.Equal(t, []string{line}, found)

	found, err = a.FindIdentities(WithOnlyNative(t.Context(), true), line)
	require.NoError(t, err)
	assert.Empty(t, found)
}

// age.ssh-key-path naming one key file, with age.sshkeys off, yields that key - it used to return
// ErrNoSSHDir because no directory was searched, discarding the key it had just parsed.
func TestGetSSHIdentitiesCustomKeyFileOnly(t *testing.T) {
	td := t.TempDir()
	t.Setenv("GOPASS_HOMEDIR", td)
	t.Setenv("GOPASS_SSH_DIR", "")
	resetSSHCache(t)

	line := writeSSHKey(t, td, "deploy_key")
	a, err := New(t.Context(), false, filepath.Join(td, "deploy_key.pub"))
	require.NoError(t, err)

	ids, err := a.getSSHIdentities(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Contains(t, ids, canonicalSSHRecipient(line))
}

func TestCanonicalSSHRecipient(t *testing.T) {
	line := writeSSHKey(t, t.TempDir(), "k")
	assert.NotContains(t, canonicalSSHRecipient(line), "test@host")
	assert.Equal(t, "age1notanssh", canonicalSSHRecipient("age1notanssh"))
}
