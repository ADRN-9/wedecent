package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreCanReplaceExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-devices.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "one", Fingerprint: "SHA256:ONE", Endpoint: "tcp://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(Peer{ID: "wd_bbbbbbbbbbbbbbbb", Name: "two", Fingerprint: "SHA256:TWO", Endpoint: "tcp://127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("wd_aaaaaaaaaaaaaaaa"); !ok {
		t.Fatal("first peer missing after replacement")
	}
	if _, ok := reopened.Get("wd_bbbbbbbbbbbbbbbb"); !ok {
		t.Fatal("second peer missing after replacement")
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	if testing.Short() {
		t.Skip("symlink test")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"peers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "trusted-devices.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
