package resolverdir

import (
	"path/filepath"
	"testing"
)

func testDir(t *testing.T) Dir {
	t.Helper()
	d, err := Load(filepath.Join("..", "..", "testdata", "resolver-dir"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return d
}

func TestLoadParsesEachKeyword(t *testing.T) {
	d := testDir(t)
	if len(d.Files) != 5 {
		t.Fatalf("files = %d, want 5", len(d.Files))
	}
	f, ok := d.ForDomain("dev.corp.internal")
	if !ok {
		t.Fatal("dev.corp.internal not found")
	}
	if len(f.Nameservers) != 1 || f.Nameservers[0] != "198.51.100.60" {
		t.Errorf("nameservers = %v", f.Nameservers)
	}
	if f.Port != 5353 {
		t.Errorf("port = %d, want 5353", f.Port)
	}

	search, _ := d.ForDomain("search.only")
	if len(search.Nameservers) != 0 || len(search.SearchDomains) != 1 {
		t.Errorf("search-only file parsed as %+v", search)
	}
}

func TestFileNameIsTheDomainUnlessOverridden(t *testing.T) {
	d := testDir(t)
	f, ok := d.ForDomain("corp.internal")
	if !ok {
		t.Fatal("corp.internal not found")
	}
	if f.Name != "corp.internal" {
		t.Errorf("name = %q", f.Name)
	}

	dir := t.TempDir()
	if err := write(filepath.Join(dir, "filename.example"), "domain other.example\nnameserver 203.0.113.1\n"); err != nil {
		t.Fatal(err)
	}
	d2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d2.ForDomain("other.example"); !ok {
		t.Error("a domain line must override the file name")
	}
}

func TestUnknownLinesAreCollected(t *testing.T) {
	d := testDir(t)
	f, ok := d.ForDomain("typo.example")
	if !ok {
		t.Fatal("typo.example not found")
	}
	if len(f.Unknown) != 1 {
		t.Fatalf("unknown lines = %v, want the nameserver typo", f.Unknown)
	}
	if len(f.Nameservers) != 0 {
		t.Errorf("a typo must not parse as a nameserver: %v", f.Nameservers)
	}
}

func TestMissingDirectoryIsNotAnError(t *testing.T) {
	d, err := Load(filepath.Join(t.TempDir(), "no-such-dir"))
	if err != nil {
		t.Fatalf("a missing resolver directory must not be an error: %v", err)
	}
	if len(d.Files) != 0 {
		t.Errorf("files = %d, want 0", len(d.Files))
	}
}
