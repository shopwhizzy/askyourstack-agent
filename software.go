package main

// What is installed on each site, with versions, for the hub's vulnerability
// feeds: WordPress plugins and themes from their file headers, and composer
// packages from composer.lock. Read as text, nothing run, nothing from the
// database. Part of the health report.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type installed struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

type siteSoftware struct {
	Root     string      `json:"root"`
	Kind     string      `json:"kind"`
	Version  string      `json:"version,omitempty"`
	Plugins  []installed `json:"plugins,omitempty"`
	Themes   []installed `json:"themes,omitempty"`
	Packages []installed `json:"packages,omitempty"`
}

var headerVersion = regexp.MustCompile(`(?mi)^[\s*#/]*Version:\s*([0-9][0-9A-Za-z.+_-]*)`)
var headerName = regexp.MustCompile(`(?mi)^[\s*#/]*(Plugin|Theme) Name:\s*\S`)

const softwareMax = 1500

// The first 8 KB of a file: enough for any header block.
func headerText(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, 8<<10)
	n, _ := f.Read(b)
	return string(b[:n])
}

// WordPress plugins: each folder under wp-content/plugins whose main file has a Plugin Name header
// (single-file plugins too); themes: style.css headers.
func wpPlugins(root string) []installed {
	dir := filepath.Join(root, "wp-content", "plugins")
	entries, _ := os.ReadDir(dir)
	var out []installed
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		var files []string
		if e.IsDir() {
			m, _ := filepath.Glob(filepath.Join(dir, name, "*.php"))
			// The file named like the folder first: it is the main file nearly always.
			sort.Slice(m, func(i, j int) bool {
				return (filepath.Base(m[i]) == name+".php") && (filepath.Base(m[j]) != name+".php")
			})
			files = m
		} else if strings.HasSuffix(name, ".php") {
			files = []string{filepath.Join(dir, name)}
			name = strings.TrimSuffix(name, ".php")
		}
		for _, f := range files {
			t := headerText(f)
			if !headerName.MatchString(t) {
				continue
			}
			v := headerVersion.FindStringSubmatch(t)
			if v != nil {
				out = append(out, installed{name, v[1]})
			}
			break
		}
		if len(out) >= softwareMax {
			break
		}
	}
	return out
}

func wpThemes(root string) []installed {
	entries, _ := os.ReadDir(filepath.Join(root, "wp-content", "themes"))
	var out []installed
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		t := headerText(filepath.Join(root, "wp-content", "themes", e.Name(), "style.css"))
		if v := headerVersion.FindStringSubmatch(t); v != nil && headerName.MatchString(t) {
			out = append(out, installed{e.Name(), v[1]})
		}
	}
	return out
}

// composer.lock packages (not the dev ones): name and version as composer resolved them.
func composerPackages(root string) []installed {
	b, err := os.ReadFile(filepath.Join(root, "composer.lock"))
	if err != nil || len(b) > 32<<20 {
		return nil
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []installed
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, installed{p.Name, strings.TrimPrefix(p.Version, "v")})
		if len(out) >= softwareMax {
			break
		}
	}
	return out
}

func softwareOf(sites []*site) []siteSoftware {
	var out []siteSoftware
	for _, s := range sites {
		if s.Container != "" {
			continue // its files are in the container; the host sees the mount only when it is a bind
		}
		sw := siteSoftware{Root: s.Root, Kind: s.Kind, Version: s.Version}
		if s.Kind == "wordpress" {
			sw.Plugins, sw.Themes = wpPlugins(s.Root), wpThemes(s.Root)
		}
		sw.Packages = composerPackages(s.Root)
		if len(sw.Plugins)+len(sw.Themes)+len(sw.Packages) > 0 {
			out = append(out, sw)
		}
	}
	return out
}
