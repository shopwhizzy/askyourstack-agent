package main

// The traffic check, every 5 minutes from the hub: the tail of each web server
// access log, summarised for the last 15 minutes (requests per minute) and the
// last 5 (who and what). The hub compares it with the server's usual rate and
// raises a bot attack alert. Reads at most tailBytes per log, never the whole file.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const tailBytes = 16 << 20

var logGlobs = []string{
	"/var/log/nginx/*access*.log", "/var/log/nginx/*/*access*.log",
	"/var/log/httpd/*access_log", "/var/log/httpd/*access*.log",
	"/var/log/apache2/*access*.log",
}

// Combined log format (nginx and Apache default): ip - user [time] "METHOD path PROTO" status bytes "referer" "agent"
var accessLine = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?`)

type hit struct {
	at     time.Time
	ip     string
	path   string
	status string
	agent  string
}

func parseAccess(line string) (hit, bool) {
	m := accessLine.FindStringSubmatch(line)
	if m == nil {
		return hit{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return hit{}, false
	}
	return hit{at: t, ip: m[1], path: m[4], status: m[5], agent: m[6]}, true
}

var staticExt = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|map|json|txt|mp4|webm)$`)

// Asset folders, whatever the extension: Luma's RequireJS fetches dozens of Knockout
// .html templates from /static/ per page view, and .html cannot go in staticExt
// (Magento's product addresses end in .html). PHP under them is no asset.
var staticDir = regexp.MustCompile(`^/(pub/)?(static|media)/|^/wp-(content|includes)/|^/skin/|^/js/`)

// What a request is for, to tell the user (and their AI) what the bots go after.
func pathClass(p string) string {
	lp := strings.ToLower(p)
	path, query, _ := strings.Cut(lp, "?")
	switch {
	case staticExt.MatchString(path) || staticDir.MatchString(path) && !strings.HasSuffix(path, ".php"):
		return "static"
	case strings.Contains(path, "/catalogsearch/") || strings.HasPrefix(path, "/search") || strings.Contains(query, "s=") && (path == "/" || path == "/index.php"):
		return "search"
	case strings.Contains(path, "/customer/account/login") || strings.Contains(path, "wp-login.php") || strings.HasSuffix(path, "/login"):
		return "login"
	case strings.Contains(path, "/customer/account/create") || strings.Contains(path, "/register") || strings.Contains(path, "action=register"):
		return "signup"
	case strings.Contains(path, "/customer/account/forgotpassword") || strings.Contains(query, "action=lostpassword"):
		return "password_reset"
	case strings.Contains(path, "/checkout") || strings.Contains(path, "/cart"):
		return "cart_checkout"
	case strings.HasPrefix(path, "/rest/") || strings.HasPrefix(path, "/graphql") || strings.HasPrefix(path, "/wp-json") || strings.Contains(path, "xmlrpc.php"):
		return "api"
	case strings.Count(query, "=") >= 2:
		return "filtered" // layered navigation and other many-parameter pages
	}
	return "pages"
}

// Lines of the last part of a file, the first (likely cut) one dropped.
func tailLines(path string, max int64) ([]string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	start, cut := int64(0), false
	if fi.Size() > max {
		start, cut = fi.Size()-max, true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, false, err
	}
	if cut {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, cut, nil
}

type counted struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

func top(m map[string]int, n int) []counted {
	out := make([]counted, 0, len(m))
	for k, v := range m {
		out = append(out, counted{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N || out[i].N == out[j].N && out[i].Key < out[j].Key })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// The machine's own addresses, read at most once a minute. A request from one
// of them is a hop between two servers on this machine (Varnish, or nginx in
// front of nginx or Apache): the front log already holds the visitor, so the
// hop would count every request twice and show this machine as the busiest
// address.
var ownCache struct {
	sync.Mutex
	at  time.Time
	set map[string]bool
}

func ownAddrs() map[string]bool {
	ownCache.Lock()
	defer ownCache.Unlock()
	if ownCache.set == nil || time.Since(ownCache.at) > time.Minute {
		set := map[string]bool{}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					set[n.IP.String()] = true
				}
			}
		}
		ownCache.set, ownCache.at = set, time.Now()
	}
	return ownCache.set
}

func ownHop(ip string, own map[string]bool) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || own[p.String()])
}

func traffic() (any, error) {
	return trafficAt(time.Now(), accessLogGlobs())
}

func trafficAt(now time.Time, globs []string) (any, error) {
	var logs []string
	seen := map[string]bool{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			if r := realPath(f); !seen[r] {
				seen[r] = true
				logs = append(logs, f)
			}
		}
	}
	minutes := make([]int, 15) // oldest first; the last one is the minute now running
	ips, classes, statuses, agents := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	last5, pages5, hops, oldest := 0, 0, 0, now
	partial := false
	own := ownAddrs()
	from := now.Add(-15 * time.Minute)
	for _, l := range logs {
		if fi, err := os.Stat(l); err != nil || fi.ModTime().Before(from) {
			continue
		}
		lines, cut, err := tailLines(l, tailBytes)
		if err != nil {
			continue
		}
		first := true
		for _, line := range lines {
			h, ok := parseAccess(line)
			if !ok {
				continue
			}
			if first && cut && h.at.After(from) {
				partial = true // this log is busier than tailBytes per 15 minutes
				if h.at.Before(oldest) {
					oldest = h.at
				}
			}
			first = false
			if h.at.Before(from) || h.at.After(now.Add(time.Minute)) {
				continue
			}
			if ownHop(h.ip, own) {
				hops++
				continue
			}
			i := 14 - int(now.Sub(h.at)/time.Minute)
			if i < 0 {
				i = 0
			}
			if i > 14 {
				i = 14
			}
			minutes[i]++
			if now.Sub(h.at) <= 5*time.Minute {
				last5++
				class := pathClass(h.path)
				classes[class]++
				// Who sends what is judged on pages only: a visitor's browser
				// fetches dozens of scripts, styles and images per page.
				if class != "static" {
					pages5++
					ips[h.ip]++
				}
				st := h.status[:1] + "xx"
				if h.status == "429" || h.status == "444" || h.status == "403" {
					st = h.status
				}
				statuses[st]++
				agents[h.agent]++
			}
		}
	}
	r := map[string]any{
		"checked_at": now.UTC().Format(time.RFC3339),
		"logs":       logs,
		"minutes":    minutes,
		"last5":      last5,
		"pages5":     pages5,
		"own_hops":   hops,
		"ips":        len(ips),
		"top_ips":    top(ips, 5),
		"classes":    classes,
		"statuses":   statuses,
		"top_agents": top(agents, 3),
		"partial":    partial,
	}
	// Covered less than 5 minutes: the hub scales the count up.
	if partial && now.Sub(oldest) < 5*time.Minute {
		r["covered_seconds"] = int(now.Sub(oldest).Seconds())
	}
	return r, nil
}
