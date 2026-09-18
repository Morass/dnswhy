// Package hostsfile reads /etc/hosts, the first thing the system resolver
// consults for a name.
package hostsfile

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// maxFileSize is far larger than any real hosts file and small enough that a
// file that is not one cannot be read into memory whole.
const maxFileSize = 8 << 20

// Entry is one name-to-address mapping, remembered with the line it came from
// so the explanation can point at it.
type Entry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Line    int    `json:"line"`
}

// Invalid is a line whose first field is not an address, so the system resolver
// ignores it. It is kept so the doctor can say the line does nothing.
type Invalid struct {
	Line    int    `json:"line"`
	Address string `json:"address"`
}

// File is a parsed hosts file.
type File struct {
	Path    string    `json:"path"`
	Entries []Entry   `json:"entries"`
	Invalid []Invalid `json:"invalid,omitempty"`
}

// Load reads and parses a hosts file. A missing file is not an error: it means
// no name is pinned.
func Load(path string) (File, error) {
	f := File{Path: path}
	// Open first, then check the descriptor: a path checked and then opened can
	// be swapped for a link or a pipe in between.
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return f, fmt.Errorf("%s could not be opened as an ordinary file: %w", path, err)
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return f, err
	}
	if !info.Mode().IsRegular() {
		return f, fmt.Errorf("%s is not an ordinary file", path)
	}
	// Truncating a hosts file would change which names it answers, so an
	// oversized one is refused rather than read in part.
	if info.Size() > maxFileSize {
		return f, fmt.Errorf("%s is %d bytes, which is not a hosts file", path, info.Size())
	}

	sc := bufio.NewScanner(io.LimitReader(fh, maxFileSize))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// An entry whose first field is not an address is ignored by the
		// system resolver, so it must not count as an answer here either.
		if net.ParseIP(fields[0]) == nil {
			f.Invalid = append(f.Invalid, Invalid{Line: n, Address: fields[0]})
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
