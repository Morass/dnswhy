// Package resolverdir reads the files in /etc/resolver. Each file names a
// domain (by its filename, unless a "domain" line says otherwise) and gives the
// nameservers for it, in resolv.conf(5) syntax. macOS folds them into the
// configuration that `scutil --dns` prints, which is why a file here can be
// present and yet have no effect.
package resolverdir

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// maxFileSize is generous for a file that holds a nameserver line or two, and
// small enough that a file left in this directory by mistake cannot be read
// into memory whole.
const maxFileSize = 1 << 20

// maxUnknown caps how many unrecognised keywords are remembered from one file.
const maxUnknown = 20

// File is one file in the resolver directory.
type File struct {
	// Err is why the file could not be read or parsed, if it could not. The
	// file still appears, so a configuration that is partly unreadable is
	// reported rather than silently shortened.
	Err string `json:"error,omitempty"`
	Path          string   `json:"path"`
	Name          string   `json:"name"`   // the file name, which is the domain by default
	Domain        string   `json:"domain"` // the domain it actually claims
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Port          int      `json:"port,omitempty"`
	Timeout       int      `json:"timeout,omitempty"`
	SearchOrder   int      `json:"search_order,omitempty"`
	// Unknown holds the first word of each line that is not a resolv.conf
	// keyword. Only the keyword is kept, never the rest of the line: a file in
	// this directory can be anything at all, and a tool that prints it would
	// print whatever it found.
	Unknown []string `json:"unknown,omitempty"`
}

// Dir is a parsed resolver directory.
type Dir struct {
	Path  string `json:"path"`
	Files []File `json:"files"`
}

// Load reads every regular file in dir. A missing directory yields no files,
// which is the common case on a Mac that has never run a VPN or dnsmasq.
func Load(dir string) (Dir, error) {
	d := Dir{Path: dir}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil
		}
		return d, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		f, err := loadFile(path, name)
		if err != nil {
			f.Err = err.Error()
		}
		d.Files = append(d.Files, f)
	}
	return d, nil
}

// kind names a file type in words a reader recognises.
func kind(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "a symbolic link"
	case m&os.ModeNamedPipe != 0:
		return "a named pipe"
	case m&os.ModeSocket != 0:
		return "a socket"
	case m&os.ModeDevice != 0:
		return "a device"
	default:
		return "not a regular file"
	}
}

func loadFile(path, name string) (File, error) {
	f := File{Path: path, Name: name, Domain: strings.ToLower(name)}
	// Open first and check the descriptor afterwards: checking the path and
	// then opening it leaves a window in which the entry can be replaced by a
	// link to something else, or by a pipe that never returns.
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return f, err
		}
		return f, fmt.Errorf("it could not be opened as an ordinary file (%v)", err)
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return f, err
	}
	if !info.Mode().IsRegular() {
		return f, fmt.Errorf("not an ordinary file (%s), so it was not read", kind(info.Mode()))
	}
	if info.Size() > maxFileSize {
		return f, fmt.Errorf("it is %d bytes, which is not a resolver file, so it was not read", info.Size())
	}

	sc := bufio.NewScanner(io.LimitReader(fh, maxFileSize))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if len(fields) > 1 {
				f.Nameservers = append(f.Nameservers, fields[1])
			}
		case "domain":
			if len(fields) > 1 {
				f.Domain = strings.TrimSuffix(strings.ToLower(fields[1]), ".")
			}
		case "search":
			for _, s := range fields[1:] {
				f.SearchDomains = append(f.SearchDomains, strings.TrimSuffix(strings.ToLower(s), "."))
			}
		case "port":
			if len(fields) > 1 {
				f.Port, _ = strconv.Atoi(fields[1])
			}
		case "timeout":
			if len(fields) > 1 {
				f.Timeout, _ = strconv.Atoi(fields[1])
			}
		case "search_order":
			if len(fields) > 1 {
				f.SearchOrder, _ = strconv.Atoi(fields[1])
			}
		case "options", "sortlist":
			// resolv.conf keywords macOS accepts but that do not change which
			// resolver is chosen.
		default:
			if len(f.Unknown) < maxUnknown {
				f.Unknown = append(f.Unknown, fields[0])
			}
		}
	}
	return f, sc.Err()
}

// ForDomain returns the file that claims a domain, if any.
func (d Dir) ForDomain(domain string) (File, bool) {
	domain = strings.ToLower(domain)
	for _, f := range d.Files {
		if f.Domain == domain {
			return f, true
		}
	}
	return File{}, false
}
