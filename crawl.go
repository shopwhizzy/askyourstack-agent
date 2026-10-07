package main

// The crawl report (crawl_report tool): what search engine and AI crawlers
// actually fetch, from the web server's access logs. Googlebot and Bingbot are
// checked by reverse DNS, since anyone can claim their user agent. Streams the
// tail of each log (at most crawlBytes), never loads it whole.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const crawlBytes = 256 << 20
const crawlKeys = 50_000 // distinct paths kept per crawler; the rest are only counted

var crawlers = []struct{ name, ua string }{
	{"Googlebot", "googlebot"}, {"Google other", "google"}, {"Bingbot", "bingbot"}, {"Applebot", "applebot"},
	{"YandexBot", "yandex"}, {"Baiduspider", "baiduspider"}, {"DuckDuckBot", "duckduckbot"},
	{"GPTBot", "gptbot"}, {"OAI-SearchBot", "oai-searchbot"}, {"ChatGPT-User", "chatgpt-user"},
	{"ClaudeBot", "claudebot"}, {"Claude-User", "claude-user"}, {"PerplexityBot", "perplexity"},
	{"Bytespider", "bytespider"}, {"Amazonbot", "amazonbot"}, {"Meta", "meta-external"}, {"CCBot", "ccbot"},
	{"AhrefsBot", "ahrefsbot"}, {"SemrushBot", "semrushbot"}, {"MJ12bot", "mj12bot"}, {"DotBot", "dotbot"},
	{"PetalBot", "petalbot"}, {"SE Ranking", "seranking"}, {"Screaming Frog", "screaming frog"},
	{"Other bot", "bot"}, {"Other bot", "crawler"}, {"Other bot", "spider"},
}

func crawlerOf(agent string) string {
	a := strings.ToLower(agent)
	for _, c := range crawlers {
		if strings.Contains(a, c.ua) {
			return c.name
		}
	}
	return ""
}

type crawlStats struct {
	Hits       int            `json:"hits"`
	Statuses   map[string]int `json:"statuses"`
	Classes    map[string]int `json:"classes"`
	WithQuery  int            `json:"with_query"`
	URLs       int            `json:"distinct_urls"`
	Top        []counted      `json:"top_paths"`
	NotFound   []counted      `json:"top_404"`
	Errors     []counted      `json:"top_5xx"`
	Redirects  []counted      `json:"top_redirects"`
	Hourly     []int          `json:"hits_per_hour,omitempty"`
	IPs        map[string]int `json:"-"`
	paths      map[string]int
	nf, er, rd map[string]int
	Verified   *verifyResult `json:"verified,omitempty"`
}

type verifyResult struct {
	Checked int      `json:"addresses_checked"`
	Genuine int      `json:"genuine_hits"`
	Fake    int      `json:"fake_hits"`
	FakeIPs []string `json:"fake_addresses,omitempty"`
	Note    string   `json:"note,omitempty"`
}

func newStats() *crawlStats {
	return &crawlStats{Statuses: map[string]int{}, Classes: map[string]int{}, IPs: map[string]int{}, paths: map[string]int{}, nf: map[string]int{}, er: map[string]int{}, rd: map[string]int{}}
}

func bump(m map[string]int, k string) {
	if _, ok := m[k]; ok || len(m) < crawlKeys {
		m[k]++
	}
}

func crawlReport(raw json.RawMessage) (any, error) {
	var a struct {
		Log   string
		Hours int
	}
	json.Unmarshal(raw, &a)
	globs := accessLogGlobs()
	if a.Log != "" {
		globs = []string{a.Log}
	}
	return crawlAt(time.Now(), globs, a.Hours, verifyCrawler)
}

func crawlAt(now time.Time, globs []string, hours int, verify func(name, ip string) bool) (any, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 168 {
		hours = 168
	}
	from := now.Add(-time.Duration(hours) * time.Hour)
	var logs []string
	seen := map[string]bool{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() && !fi.ModTime().Before(from) && !seen[realPath(f)] {
				seen[realPath(f)] = true
				logs = append(logs, f)
			}
		}
	}
	if len(logs) == 0 {
		return nil, fmt.Errorf("no access log changed in the last %d hours (looked in %s); pass log with the site's access log path", hours, strings.Join(globs, ", "))
	}
	bots := map[string]*crawlStats{}
	total, humans, hops := 0, 0, 0
	own := ownAddrs()
	oldest := now
	partial := false
	for _, l := range logs {
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		fi, _ := f.Stat()
		cut := fi.Size() > crawlBytes
		if cut {
			f.Seek(fi.Size()-crawlBytes, io.SeekStart)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		first := cut
		for sc.Scan() {
			if first { // a cut line
				first = false
				continue
			}
			h, ok := parseAccess(sc.Text())
			if !ok {
				continue
			}
			if cut && !partial && h.at.After(from) {
				partial = true
				if h.at.Before(oldest) {
					oldest = h.at
				}
			}
			cut = false
			if h.at.Before(from) || h.at.After(now.Add(time.Minute)) {
				continue
			}
			if ownHop(h.ip, own) { // Varnish or a proxy on this machine: the front log has it
				hops++
				continue
			}
			total++
			name := crawlerOf(h.agent)
			if name == "" {
				humans++
				continue
			}
			s := bots[name]
			if s == nil {
				s = newStats()
				if name == "Googlebot" || name == "Bingbot" {
					s.Hourly = make([]int, hours)
				}
				bots[name] = s
			}
			s.Hits++
			st := h.status[:1] + "xx"
			if h.status == "404" || h.status == "410" || h.status == "429" || h.status == "403" {
				st = h.status
			}
			s.Statuses[st]++
			s.Classes[pathClass(h.path)]++
			if strings.Contains(h.path, "?") {
				s.WithQuery++
			}
			p := h.path
			if len(p) > 200 {
				p = p[:200]
			}
			bump(s.paths, p)
			switch {
			case h.status == "404" || h.status == "410":
				bump(s.nf, p)
			case h.status[0] == '5':
				bump(s.er, p)
			case h.status[0] == '3':
				bump(s.rd, p)
			}
			bump(s.IPs, h.ip)
			if s.Hourly != nil {
				if i := hours - 1 - int(now.Sub(h.at)/time.Hour); i >= 0 && i < hours {
					s.Hourly[i]++
				}
			}
		}
		f.Close()
	}
	out := map[string]any{}
	for name, s := range bots {
		s.URLs = len(s.paths)
		s.Top, s.NotFound, s.Errors, s.Redirects = top(s.paths, 20), top(s.nf, 10), top(s.er, 10), top(s.rd, 10)
		if name == "Googlebot" || name == "Bingbot" {
			s.Verified = checkIPs(name, s.IPs, verify)
		}
		out[name] = s
	}
	r := map[string]any{
		"logs": logs, "hours": hours, "from": from.UTC().Format(time.RFC3339),
		"requests": total, "not_crawlers": humans, "own_hops": hops, "crawlers": out,
	}
	if partial {
		r["note"] = fmt.Sprintf("the logs are busier than %d MB for this period: counts start at %s", crawlBytes>>20, oldest.UTC().Format(time.RFC3339))
	}
	return r, nil
}

// The busiest 20 addresses claiming to be the crawler, by reverse then forward DNS.
func checkIPs(name string, ips map[string]int, verify func(name, ip string) bool) *verifyResult {
	v := &verifyResult{}
	list := top(ips, 20)
	checked := 0
	for _, c := range list {
		checked += c.N
		v.Checked++
		if verify(name, c.Key) {
			v.Genuine += c.N
		} else {
			v.Fake += c.N
			v.FakeIPs = append(v.FakeIPs, c.Key)
		}
	}
	sum := 0
	for _, n := range ips {
		sum += n
	}
	if sum > checked {
		v.Note = fmt.Sprintf("%d hits from %d less busy addresses were not checked", sum-checked, len(ips)-len(list))
	}
	sort.Strings(v.FakeIPs)
	return v
}

func verifyCrawler(name, ip string) bool {
	suffixes := []string{".googlebot.com.", ".google.com.", ".googleusercontent.com."}
	if name == "Bingbot" {
		suffixes = []string{".search.msn.com."}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return false
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".") {
			n += "."
		}
		ok := false
		for _, s := range suffixes {
			ok = ok || strings.HasSuffix(strings.ToLower(n), s)
		}
		if !ok {
			continue
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if net.ParseIP(a).Equal(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}
