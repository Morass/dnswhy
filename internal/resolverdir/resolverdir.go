// Package resolverdir reads the files in /etc/resolver. Each file names a
// domain (by its filename, unless a "domain" line says otherwise) and gives the
// nameservers for it, in resolv.conf(5) syntax. macOS folds them into the
// configuration that `scutil --dns` prints, which is why a file here can be
// present and yet have no effect.
package resolverdir

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// File is one file in the resolver directory.
type File struct {
	Path          string   `json:"path"`
	Name          string   `json:"name"`   // the file name, which is the domain by default
	Domain        string   `json:"domain"` // the domain it actually claims
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Port          int      `json:"port,omitempty"`
	Timeout       int      `json:"timeout,omitempty"`
	SearchOrder   int      `json:"search_order,omitempty"`
	Unknown       []string `json:"unknown,omitempty"` // lines that are not resolv.conf keywords
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
		f, err := loadFile(filepath.Join(dir, name), name)
		if err != nil {
			continue // unreadable files are reported by the doctor, not fatal here
		}
		d.Files = append(d.Files, f)
	}
	return d, nil
}

func loadFile(path, name string) (File, error) {
	f := File{Path: path, Name: name, Domain: strings.ToLower(name)}
	fh, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer fh.Close()

	sc := bufio.NewScanner(fh)
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
			f.Unknown = append(f.Unknown, strings.TrimSpace(line))
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
