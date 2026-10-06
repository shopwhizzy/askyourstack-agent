package main

// Where the web server itself says the sites are: nginx server blocks and
// Apache virtual hosts, read from their configuration files with includes
// followed. Each gives the domains, the folders it serves and its access logs.
// Site detection (sites.go) looks in these folders besides the usual ones, so
// a site is found wherever the hosting panel put it, and the crawl and traffic
// reports read these logs besides /var/log.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type vhost struct {
	Server  string   // nginx | apache
	Names   []string // domains, wildcards and catch-alls left out
	Roots   []string // the document root first, then other folders the block names
	Logs    []string
	ErrLogs []string // error logs, for the logs tool
}

var (
	nginxConfs  = []string{"/etc/nginx/nginx.conf"}
	apacheConfs = []string{"/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf", "/etc/apache2/conf/httpd.conf", "/usr/local/apache/conf/httpd.conf"}
)

// A panel with thousands of sites has a lot of configuration; stop reading here.
const confBudget = 16 << 20

var (
	confComment   = regexp.MustCompile(`(?m)(^|\s)#.*$`)
	nginxInclude  = regexp.MustCompile(`(?m)(?:^|[\s;{}])include\s+([^;]+);`)
	apacheInclude = regexp.MustCompile(`(?im)^\s*Include(?:Optional)?\s+("[^"]+"|\S+)`)

	nginxServer  = regexp.MustCompile(`(?m)(?:^|[\s;{}])server\s*\{`)
	nginxSet     = regexp.MustCompile(`(?m)(?:^|[\s;{}])set\s+\$(\w+)\s+([^;\s]+)\s*;`)
	nginxRoot    = regexp.MustCompile(`(?m)(?:^|[\s;{}])root\s+([^;]+);`)
	nginxName    = regexp.MustCompile(`(?m)(?:^|[\s;{}])server_name\s+([^;]+);`)
	nginxLog     = regexp.MustCompile(`(?m)(?:^|[\s;{}])access_log\s+([^;\s]+)`)
	nginxErrLog  = regexp.MustCompile(`(?m)(?:^|[\s;{}])error_log\s+([^;\s]+)`)
	apacheErrLog = regexp.MustCompile(`(?im)^\s*ErrorLog\s+("[^"]+"|\S+)`)
	nginxVar     = regexp.MustCompile(`\$\{?(\w+)\}?`)

	apacheVhost = regexp.MustCompile(`(?is)<VirtualHost\b[^>]*>(.*?)</VirtualHost>`)
	apacheName  = regexp.MustCompile(`(?im)^\s*ServerName\s+(\S+)`)
	apacheAlias = regexp.MustCompile(`(?im)^\s*ServerAlias\s+(.+)$`)
	apacheRoot  = regexp.MustCompile(`(?im)^\s*DocumentRoot\s+("[^"]+"|\S+)`)
	apacheLog   = regexp.MustCompile(`(?im)^\s*(?:CustomLog|TransferLog)\s+("[^"]+"|\S+)`)
)

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

// confText returns a configuration file with the files it includes put in place.
// A file is read once: a snippet shared by many sites adds nothing the second time.
func confText(path, base string, include *regexp.Regexp, left *int, seen map[string]bool, depth int) string {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || seen[real] || depth > 8 {
		return ""
	}
	seen[real] = true
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() || int(fi.Size()) > *left {
		return ""
	}
	b, err := os.ReadFile(real)
	if err != nil {
		return ""
	}
	*left -= len(b)
	text := confComment.ReplaceAllString(string(b), "$1")
	return include.ReplaceAllStringFunc(text, func(m string) string {
		arg := unquote(include.FindStringSubmatch(m)[1])
		if arg == "" {
			return ""
		}
		if !filepath.IsAbs(arg) {
			arg = filepath.Join(base, arg)
		}
		if fi, err := os.Stat(arg); err == nil && fi.IsDir() {
			arg = filepath.Join(arg, "*")
		}
		files, _ := filepath.Glob(arg)
		var sb strings.Builder
		sb.WriteString("\n")
		for _, f := range files {
			sb.WriteString(confText(f, base, include, left, seen, depth+1))
			sb.WriteString("\n")
		}
		return sb.String()
	})
}

// nginxBlocks returns the inside of every server { } block.
func nginxBlocks(text string) []string {
	var out []string
	for _, loc := range nginxServer.FindAllStringIndex(text, -1) {
		depth, i := 1, loc[1]
		var quote byte
		for ; i < len(text) && depth > 0; i++ {
			c := text[i]
			switch {
			case quote != 0:
				if c == '\\' {
					i++
				} else if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '{':
				depth++
			case c == '}':
				depth--
			}
		}
		out = append(out, text[loc[1]:min(i, len(text))])
	}
	return out
}

func addOnce(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// A name a person would call the site by: no catch-alls, wildcards or patterns.
func hostName(n string) string {
	n = strings.ToLower(unquote(n))
	n = strings.TrimPrefix(strings.TrimPrefix(n, "https://"), "http://")
	n, _, _ = strings.Cut(n, "/")
	if i := strings.LastIndex(n, ":"); i > 0 && !strings.Contains(n, "]") {
		n = n[:i]
	}
	if n == "" || n == "_" || n == "localhost" || strings.ContainsAny(n, "*~$^()[]\\ ") || !strings.Contains(n, ".") || strings.HasPrefix(n, ".") {
		return ""
	}
	return n
}

func parseNginx(text string) []vhost {
	var out []vhost
	for _, block := range nginxBlocks(text) {
		v := vhost{Server: "nginx"}
		vars := map[string]string{}
		for _, m := range nginxSet.FindAllStringSubmatch(block, -1) {
			vars[m[1]] = unquote(m[2])
		}
		expand := func(s string) string {
			return nginxVar.ReplaceAllStringFunc(unquote(s), func(ref string) string {
				if val, ok := vars[nginxVar.FindStringSubmatch(ref)[1]]; ok {
					return val
				}
				return ref
			})
		}
		for _, m := range nginxRoot.FindAllStringSubmatch(block, -1) {
			if r := expand(m[1]); filepath.IsAbs(r) && !strings.Contains(r, "$") {
				v.Roots = addOnce(v.Roots, filepath.Clean(r))
			}
		}
		// Magento's sample configuration keeps the root in a variable (set $MAGE_ROOT ...).
		for _, val := range vars {
			if filepath.IsAbs(val) && !strings.Contains(val, "$") {
				v.Roots = addOnce(v.Roots, filepath.Clean(val))
			}
		}
		for _, m := range nginxName.FindAllStringSubmatch(block, -1) {
			for _, n := range strings.Fields(m[1]) {
				if h := hostName(n); h != "" {
					v.Names = addOnce(v.Names, h)
				}
			}
		}
		for _, m := range nginxLog.FindAllStringSubmatch(block, -1) {
			if l := unquote(m[1]); filepath.IsAbs(l) && !strings.Contains(l, "$") {
				v.Logs = addOnce(v.Logs, filepath.Clean(l))
			}
		}
		for _, m := range nginxErrLog.FindAllStringSubmatch(block, -1) {
			if l := unquote(m[1]); filepath.IsAbs(l) && !strings.Contains(l, "$") {
				v.ErrLogs = addOnce(v.ErrLogs, filepath.Clean(l))
			}
		}
		if len(v.Roots) > 0 || (len(v.Names) > 0 && len(v.Logs) > 0) {
			out = append(out, v)
		}
	}
	return out
}

func parseApache(text, serverRoot string) []vhost {
	var out []vhost
	for _, b := range apacheVhost.FindAllStringSubmatch(text, -1) {
		block := b[1]
		v := vhost{Server: "apache"}
		if m := apacheName.FindStringSubmatch(block); m != nil {
			if h := hostName(m[1]); h != "" {
				v.Names = addOnce(v.Names, h)
			}
		}
		for _, m := range apacheAlias.FindAllStringSubmatch(block, -1) {
			for _, n := range strings.Fields(m[1]) {
				if h := hostName(n); h != "" {
					v.Names = addOnce(v.Names, h)
				}
			}
		}
		if m := apacheRoot.FindStringSubmatch(block); m != nil {
			if r := unquote(m[1]); filepath.IsAbs(r) && !strings.Contains(r, "$") {
				v.Roots = []string{filepath.Clean(r)}
			}
		}
		for _, m := range apacheLog.FindAllStringSubmatch(block, -1) {
			l := strings.ReplaceAll(unquote(m[1]), "${APACHE_LOG_DIR}", "/var/log/apache2")
			if l == "" || strings.HasPrefix(l, "|") || strings.ContainsAny(l, "$%") {
				continue // piped to a program, or a path only Apache can work out
			}
			if !filepath.IsAbs(l) {
				l = filepath.Join(serverRoot, l)
			}
			v.Logs = addOnce(v.Logs, filepath.Clean(l))
		}
		for _, m := range apacheErrLog.FindAllStringSubmatch(block, -1) {
			l := strings.ReplaceAll(unquote(m[1]), "${APACHE_LOG_DIR}", "/var/log/apache2")
			if l == "" || strings.HasPrefix(l, "|") || strings.HasPrefix(l, "syslog") || strings.ContainsAny(l, "$%") {
				continue
			}
			if !filepath.IsAbs(l) {
				l = filepath.Join(serverRoot, l)
			}
			v.ErrLogs = addOnce(v.ErrLogs, filepath.Clean(l))
		}
		if len(v.Roots) > 0 {
			out = append(out, v)
		}
	}
	return out
}

func readVhosts() []vhost {
	var out []vhost
	left := confBudget
	seen := map[string]bool{}
	for _, c := range nginxConfs {
		out = append(out, parseNginx(confText(c, filepath.Dir(c), nginxInclude, &left, seen, 0))...)
	}
	for _, c := range apacheConfs {
		root := filepath.Dir(c)
		if filepath.Base(root) == "conf" {
			root = filepath.Dir(root)
		}
		out = append(out, parseApache(confText(c, root, apacheInclude, &left, seen, 0), root)...)
	}
	return out
}

// Read at most once a minute: site tools ask on every call.
var vhostCache struct {
	sync.Mutex
	at   time.Time
	list []vhost
}

func vhosts() []vhost {
	vhostCache.Lock()
	defer vhostCache.Unlock()
	if vhostCache.at.IsZero() || time.Since(vhostCache.at) > time.Minute {
		vhostCache.list, vhostCache.at = readVhosts(), time.Now()
	}
	return vhostCache.list
}

// frontLogs drops Apache's logs for domains nginx also serves: with nginx in
// front (Plesk, cPanel with nginx) both write the same request, and counting
// both would double the traffic.
func frontLogs(all []vhost) []vhost {
	fronted := map[string]bool{}
	for _, v := range all {
		if v.Server == "nginx" && len(v.Logs) > 0 {
			for _, n := range v.Names {
				fronted[n] = true
			}
		}
	}
	var out []vhost
	for _, v := range all {
		if v.Server == "apache" {
			behind := false
			for _, n := range v.Names {
				behind = behind || fronted[n]
			}
			if behind {
				v.Logs = nil
			}
		}
		out = append(out, v)
	}
	return out
}

// accessLogGlobs is every access log worth reading: the usual folders plus
// the logs the virtual hosts name (panels keep them next to each site).
func accessLogGlobs() []string {
	globs := append([]string{}, logGlobs...)
	for _, v := range frontLogs(vhosts()) {
		for _, l := range v.Logs {
			if !strings.ContainsAny(l, "*?[") {
				globs = addOnce(globs, l)
			}
		}
	}
	return globs
}

// realPath is the path with symbolic links followed, so one file or folder
// reached two ways counts once.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// vhostsOf fills in a site's domains and access logs from the virtual hosts
// that serve its folder (or its pub, public or web folder).
func vhostsOf(s *site, all []vhost) {
	root := realPath(s.Root)
	for _, v := range all {
		serves := false
		for _, r := range v.Roots {
			r = realPath(r)
			if r == root {
				serves = true
			} else if b := filepath.Base(r); filepath.Dir(r) == root && (b == "pub" || b == "public" || b == "web") {
				serves = true
			}
		}
		if !serves {
			continue
		}
		for _, n := range v.Names {
			s.Domains = addOnce(s.Domains, n)
		}
		for _, l := range v.Logs {
			s.AccessLogs = addOnce(s.AccessLogs, l)
		}
	}
}
