package hostsfile

import (
	"path/filepath"
	"testing"
)

func TestLoadAndLookup(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "testdata", "hosts"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := f.Lookup("PINNED.corp.internal")
	if len(got) != 1 {
		t.Fatalf("lookup gave %d entries, want 1", len(got))
	}
	if got[0].Address != "198.51.100.9" || got[0].Line != 7 {
		t.Errorf("entry = %+v, want 198.51.100.9 on line 7", got[0])
	}
	if n := len(f.Lookup("localhost")); n != 2 {
		t.Errorf("localhost has %d entries, want 2 (v4 and v6)", n)
	}
	if n := len(f.Lookup("absent.example")); n != 0 {
		t.Errorf("absent name gave %d entries", n)
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "nothing-here"))
	if err != nil {
		t.Fatalf("a missing hosts file must not be an error: %v", err)
	}
	if len(f.Entries) != 0 {
		t.Errorf("entries = %d, want 0", len(f.Entries))
	}
}

func TestCommentsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := writeFile(path, "203.0.113.1 real.example # 203.0.113.2 commented.example\n#203.0.113.3 hidden.example\n"); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 || f.Entries[0].Name != "real.example" {
		t.Errorf("entries = %+v", f.Entries)
	}
}
