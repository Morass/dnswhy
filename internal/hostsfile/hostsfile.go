// Package hostsfile reads /etc/hosts, the first thing the system resolver
// consults for a name.
package hostsfile

import (
	"bufio"
	"os"
	"strings"
)

// Entry is one name-to-address mapping, remembered with the line it came from
// so the explanation can point at it.
type Entry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Line    int    `json:"line"`
}

// File is a parsed hosts file.
type File struct {
	Path    string  `json:"path"`
	Entries []Entry `json:"entries"`
}

// Load reads and parses a hosts file. A missing file is not an error: it means
// no name is pinned.
func Load(path string) (File, error) {
	f := File{Path: path}
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return f, err
	}
	defer fh.Close()

	sc := bufio.NewScanner(fh)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			f.Entries = append(f.Entries, Entry{
				Name:    strings.TrimSuffix(strings.ToLower(name), "."),
				Address: fields[0],
				Line:    n,
			})
		}
	}
	return f, sc.Err()
}

// Lookup returns every entry for a name, case-insensitively.
func (f File) Lookup(name string) []Entry {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var out []Entry
	for _, e := range f.Entries {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}
