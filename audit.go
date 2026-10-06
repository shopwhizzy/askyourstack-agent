package main

// Site audit: walk one site link by link from the server it runs on, the way a
// search engine would, and keep what every page answered so the AI can ask by
// issue afterwards (broken links, redirects, missing or repeated titles, pages
// kept out of the index, what the sitemap lists against what is linked).
// Fetching from the server itself goes straight to the local web server, so a
// CDN or firewall in front of the site does not block or slow it, and nothing
// is fetched from outside the site. Runs as a background job (siteaudit).

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var auditDir = stateDir("audits")

const (
	auditAgent    = "Mozilla/5.0 (compatible; SudoWhizzy-SiteAudit/1.0; +https://sudowhizzy.com)"
	auditBodyMax  = 3 << 20
	auditMaxPages = 5000
	auditKeepRuns = 5
	auditRefs     = 5
	auditPerIssue = 2000
)

type auditArgs struct {
	Site     string `json:"site"`
	URL      string `json:"url"`
	MaxPages int    `json:"max_pages"`
	Via      string `json:"via"`         // auto | local | public
	Workers  int    `json:"concurrency"` // pages fetched at the same time
	Params   string `json:"query_urls"`  // sample | all | none
	Minutes  int    `json:"minutes"`
}

type auditPage struct {
	URL       string   `json:"url"`
	Status    int      `json:"status"`
	Redirect  string   `json:"redirect,omitempty"`
	Type      string   `json:"type,omitempty"`
	Bytes     int      `json:"bytes,omitempty"`
	Ms        int      `json:"ms,omitempty"`
	Depth     int      `json:"depth"` // clicks from the start page; -1 = only the sitemap names it
	Inlinks   int      `json:"inlinks"`
	Refs      []string `json:"linked_from,omitempty"` // the first few pages that link here
	Title     string   `json:"title,omitempty"`
	Desc      string   `json:"description,omitempty"`
	H1        string   `json:"h1,omitempty"`
	H1s       int      `json:"h1_count,omitempty"`
	Canonical string   `json:"canonical,omitempty"`
	Robots    string   `json:"robots,omitempty"`
	Lang      string   `json:"lang,omitempty"`
	Hreflang  int      `json:"hreflang,omitempty"`
	Words     int      `json:"words,omitempty"`
	Links     int      `json:"internal_links,omitempty"`
	External  int      `json:"external_links,omitempty"`
	Images    int      `json:"images,omitempty"`
	NoAlt     int      `json:"images_without_alt,omitempty"`
	Schema    []string `json:"schema,omitempty"`
	Sitemap   bool     `json:"in_sitemap,omitempty"`
	Note      string   `json:"note,omitempty"` // why it was not fetched, or what went wrong
	hash      string
	viewport  bool
	insecure  int // links to http:// pages of this same site
	html      bool
	queued    bool
}

type auditItem struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

type auditIssue struct {
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Severity string      `json:"severity"` // high | medium | low
	Why      string      `json:"why"`
	Count    int         `json:"count"`
	Items    []auditItem `json:"items,omitempty"`
}

type auditRun struct {
	Run      string         `json:"run"`
	Host     string         `json:"host"`
	Start    string         `json:"start_url"`
	Started  string         `json:"started"`
	Finished string         `json:"finished"`
	Via      string         `json:"fetched"`
	Stats    map[string]any `json:"stats"`
	Issues   []auditIssue   `json:"issues"`
	Pages    []*auditPage   `json:"pages"`
}

// --- starting it (op audit_start)

// siteAddress: where the site lives, as the site itself says (its database or configuration).
func siteAddress(s *site) string {
	if v := kindOf(s.Kind).Address(s); v != "" {
		return v
	}
	return fromDomain(s)
}

func auditStartURL(a *auditArgs) (*url.URL, error) {
	start := strings.TrimSpace(a.URL)
	if start == "" {
		s, err := pickSite(a.Site)
		if err != nil {
			if a.Site == "" {
				return nil, errors.New("pass url (the address to start from, like https://www.example.com/) or site")
			}
			return nil, err
		}
		if start = siteAddress(s); start == "" {
			return nil, errors.New("could not tell this site's address; pass url")
		}
	}
	if !strings.Contains(start, "://") {
		start = "https://" + start
	}
	u, err := url.Parse(start)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("url must be a full address, like https://www.example.com/")
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func auditStart(raw json.RawMessage) (any, error) {
	var a auditArgs
	json.Unmarshal(raw, &a)
	u, err := auditStartURL(&a)
	if err != nil {
		return nil, err
	}
	a.URL, a.Site = u.String(), ""
	if a.MaxPages <= 0 {
		a.MaxPages = 500
	}
	a.MaxPages = min(a.MaxPages, auditMaxPages)
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(auditDir, "args-*.json")
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(a)
	f.Write(b)
	f.Close()
	jb, _ := json.Marshal(map[string]string{"command": fmt.Sprintf("%s siteaudit %s", shellQuote(self), shellQuote(f.Name())), "name": "site-audit"})
	res, err := jobStart(jb)
	if err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	r := res.(map[string]any)
	r["start_url"], r["max_pages"] = a.URL, a.MaxPages
	r["next"] = "The audit runs in the background (a few pages a second). Call job_output with this job_id until status is finished; its last lines are the summary. Then ask site_audit_report for the pages behind each issue."
	return r, nil
}

// --- fetching

type auditFetcher struct {
	client *http.Client
	plain  bool // the local web server only answers on port 80: https pages are asked there, marked as https
	via    string
}

type auditResp struct {
	status int
	header http.Header
	body   []byte
	ms     int
	err    string
}

func (f *auditFetcher) get(u string) auditResp {
	ask := u
	if f.plain && strings.HasPrefix(u, "https://") {
		ask = "http://" + strings.TrimPrefix(u, "https://")
	}
	req, err := http.NewRequest("GET", ask, nil)
	if err != nil {
		return auditResp{err: err.Error()}
	}
	req.Header.Set("User-Agent", auditAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5")
	if ask != u {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	t0 := time.Now()
	res, err := f.client.Do(req)
	if err != nil {
		msg := err.Error()
		if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 120 {
			msg = msg[i+2:]
		}
		return auditResp{err: msg, ms: int(time.Since(t0).Milliseconds())}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, auditBodyMax))
	return auditResp{status: res.StatusCode, header: res.Header, body: body, ms: int(time.Since(t0).Milliseconds())}
}

func auditClient(dialTo string) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{MaxIdleConnsPerHost: 8, ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	if dialTo != "" {
		// Straight to this machine's web server, whatever the name resolves to. Its
		// certificate may be one only the CDN trusts, so it is not checked here.
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return d.DialContext(ctx, network, net.JoinHostPort(dialTo, port))
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		tr.DialContext = d.DialContext
	}
	return &http.Client{Transport: tr, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func sameSite(a, b string) bool {
	return strings.TrimPrefix(strings.ToLower(a), "www.") == strings.TrimPrefix(strings.ToLower(b), "www.")
}

// servedHere: does this machine's web server configuration name the host?
func servedHere(host string) bool {
	for _, v := range vhosts() {
		for _, n := range v.Names {
			if sameSite(hostName(n), host) {
				return true
			}
		}
	}
	return false
}

func localAddrs() []string {
	out := []string{"127.0.0.1"}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			out = append(out, n.IP.String())
		}
	}
	return out
}

// newAuditFetcher picks how pages are fetched: from this machine's own web
// server when it serves the site and answers for it, else over the internet.
func newAuditFetcher(start *url.URL, via string) (*auditFetcher, error) {
	tryLocal := via == "local" || (via != "public" && servedHere(start.Hostname()))
	if tryLocal {
		for _, plain := range []bool{false, true} {
			if plain && start.Scheme != "https" {
				break
			}
			for _, ip := range localAddrs() {
				f := &auditFetcher{client: auditClient(ip), plain: plain, via: "from this server's own web server (" + ip + ")"}
				f.client.Timeout = 15 * time.Second
				r := f.get(start.String())
				ok := r.status == 200
				if r.status >= 300 && r.status < 400 {
					if to, err := start.Parse(r.header.Get("Location")); err == nil && sameSite(to.Hostname(), start.Hostname()) && to.String() != start.String() {
						ok = true
					}
				}
				if ok {
					f.client.Timeout = 40 * time.Second
					return f, nil
				}
			}
		}
		if via == "local" {
			return nil, errors.New("this server's own web server does not answer for " + start.Hostname() + "; use via \"public\"")
		}
	}
	return &auditFetcher{client: auditClient(""), via: "over the internet, as a visitor would"}, nil
}

// --- reading a page

type pageFacts struct {
	title, desc, canonical, robots, lang, base string
	h1                                         []string
	links                                      []string
	images, noAlt, hreflang, words             int
	schema                                     []string
	viewport                                   bool
	hash                                       string
}

var (
	spaces     = regexp.MustCompile(`\s+`)
	rawText    = map[string]bool{"script": true, "style": true, "textarea": true, "title": true, "noscript": true, "template": true}
	chromeTags = map[string]bool{"nav": true, "header": true, "footer": true, "aside": true}
)

func tidyText(s string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(html.UnescapeString(s), " "))
}

// tagAt reads the tag that starts at doc[i] ('<'): its name, attributes and
// where it ends. Quotes are honoured, since attribute values may hold '>'.
func tagAt(doc string, i int) (name string, attrs map[string]string, closing bool, end int, ok bool) {
	j := i + 1
	if j < len(doc) && doc[j] == '/' {
		closing = true
		j++
	}
	k := j
	for k < len(doc) && (doc[k] == '-' || doc[k] == ':' || doc[k] >= '0' && doc[k] <= '9' || doc[k]|0x20 >= 'a' && doc[k]|0x20 <= 'z') {
		k++
	}
	if k == j {
		return "", nil, false, i + 1, false
	}
	name = strings.ToLower(doc[j:k])
	attrs = map[string]string{}
	for k < len(doc) {
		for k < len(doc) && (doc[k] == ' ' || doc[k] == '\n' || doc[k] == '\t' || doc[k] == '\r' || doc[k] == '/') {
			k++
		}
		if k >= len(doc) {
			break
		}
		if doc[k] == '>' {
			return name, attrs, closing, k + 1, true
		}
		a := k
		for k < len(doc) && !strings.ContainsRune(" \n\t\r=>/", rune(doc[k])) {
			k++
		}
		if k == a { // a stray character: step over it
			k++
			continue
		}
		key := strings.ToLower(doc[a:k])
		for k < len(doc) && (doc[k] == ' ' || doc[k] == '\n' || doc[k] == '\t' || doc[k] == '\r') {
			k++
		}
		val := ""
		if k < len(doc) && doc[k] == '=' {
			k++
			for k < len(doc) && (doc[k] == ' ' || doc[k] == '\n' || doc[k] == '\t' || doc[k] == '\r') {
				k++
			}
			if k < len(doc) && (doc[k] == '"' || doc[k] == '\'') {
				q := doc[k]
				e := strings.IndexByte(doc[k+1:], q)
				if e < 0 {
					return name, attrs, closing, len(doc), true
				}
				val = doc[k+1 : k+1+e]
				k += e + 2
			} else {
				a := k
				for k < len(doc) && !strings.ContainsRune(" \n\t\r>", rune(doc[k])) {
					k++
				}
				val = doc[a:k]
			}
		}
		if _, dup := attrs[key]; !dup {
			attrs[key] = html.UnescapeString(val)
		}
	}
	return name, attrs, closing, len(doc), true
}

func schemaTypes(raw string, into []string) []string {
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &v) != nil {
		return addOnce(into, "(JSON-LD that does not parse)")
	}
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 6 || len(into) >= 12 {
			return
		}
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				walk(x, depth+1)
			}
		case map[string]any:
			switch ty := t["@type"].(type) {
			case string:
				into = addOnce(into, ty)
			case []any:
				for _, x := range ty {
					if s, ok := x.(string); ok {
						into = addOnce(into, s)
					}
				}
			}
			if g, ok := t["@graph"]; ok {
				walk(g, depth+1)
			}
		}
	}
	walk(v, 0)
	return into
}

func readPage(body []byte) *pageFacts {
	doc := string(body)
	f := &pageFacts{}
	var text strings.Builder // the page's own words: no menus, header or footer
	var h1 strings.Builder
	inH1, chrome, sawBody := false, 0, false
	add := func(s string) {
		if inH1 {
			h1.WriteString(s)
		}
		if sawBody && chrome == 0 && text.Len() < 400_000 {
			text.WriteString(s)
			text.WriteByte(' ')
		}
	}
	for i := 0; i < len(doc); {
		lt := strings.IndexByte(doc[i:], '<')
		if lt < 0 {
			add(doc[i:])
			break
		}
		add(doc[i : i+lt])
		i += lt
		if strings.HasPrefix(doc[i:], "<!--") {
			e := strings.Index(doc[i+4:], "-->")
			if e < 0 {
				break
			}
			i += e + 7
			continue
		}
		if i+1 < len(doc) && (doc[i+1] == '!' || doc[i+1] == '?') {
			e := strings.IndexByte(doc[i:], '>')
			if e < 0 {
				break
			}
			i += e + 1
			continue
		}
		name, at, closing, end, ok := tagAt(doc, i)
		if !ok {
			add("<")
			i = end
			continue
		}
		i = end
		if closing {
			switch {
			case name == "h1" && inH1:
				inH1 = false
				if t := tidyText(h1.String()); t != "" || len(f.h1) == 0 {
					f.h1 = append(f.h1, t)
				}
				h1.Reset()
			case chromeTags[name] && chrome > 0:
				chrome--
			}
			continue
		}
		if rawText[name] {
			// What is inside is not markup: take it whole, up to the closing tag.
			low := strings.ToLower(doc[i:min(len(doc), i+auditBodyMax)])
			e := strings.Index(low, "</"+name)
			inner := doc[i:]
			if e >= 0 {
				inner = doc[i : i+e]
				i += e
			} else {
				i = len(doc)
			}
			switch {
			case name == "title" && f.title == "" && !sawBody:
				f.title = tidyText(inner)
			case name == "script" && strings.Contains(strings.ToLower(at["type"]), "ld+json"):
				f.schema = schemaTypes(inner, f.schema)
			}
			continue
		}
		switch name {
		case "html":
			f.lang = at["lang"]
		case "body":
			sawBody = true
		case "base":
			if f.base == "" {
				f.base = at["href"]
			}
		case "meta":
			n := strings.ToLower(at["name"])
			switch {
			case n == "description" && f.desc == "":
				f.desc = tidyText(at["content"])
			case n == "robots" || n == "googlebot":
				f.robots = strings.TrimSpace(f.robots + " " + strings.ToLower(at["content"]))
			case n == "viewport":
				f.viewport = true
			}
		case "link":
			rel := " " + strings.ToLower(at["rel"]) + " "
			if strings.Contains(rel, " canonical ") && f.canonical == "" {
				f.canonical = strings.TrimSpace(at["href"])
			}
			if strings.Contains(rel, " alternate ") && at["hreflang"] != "" {
				f.hreflang++
			}
		case "a":
			if h, ok := at["href"]; ok {
				f.links = append(f.links, h)
			}
		case "img":
			f.images++
			if _, ok := at["alt"]; !ok {
				f.noAlt++
			}
		case "h1":
			inH1 = true
			h1.Reset()
		default:
			if chromeTags[name] {
				chrome++
			}
		}
	}
	words := strings.Fields(html.UnescapeString(text.String()))
	f.words = len(words)
	if f.words >= 50 {
		sum := sha1.Sum([]byte(strings.ToLower(strings.Join(words, " "))))
		f.hash = hex.EncodeToString(sum[:8])
	}
	return f
}

// --- addresses

var (
	trackingParam = regexp.MustCompile(`(?i)^(utm_[a-z]+|gclid|gbraid|wbraid|fbclid|msclkid|mc_cid|mc_eid|_ga|_gl|yclid)$`)
	assetExt      = regexp.MustCompile(`(?i)\.(jpe?g|png|gif|webp|avif|svg|ico|bmp|css|js|mjs|map|json|xml|rss|atom|pdf|zip|gz|rar|7z|tar|docx?|xlsx?|pptx?|csv|txt|mp[34]|webm|mov|avi|woff2?|ttf|eot|otf|exe|dmg|apk)$`)
)

// cleanURL resolves a link against its page and brings it to one spelling: no
// fragment, no tracking parameters, lower-case host.
func cleanURL(base *url.URL, href string) *url.URL {
	href = strings.TrimSpace(href)
	if href == "" || href[0] == '#' || len(href) > 2000 {
		return nil
	}
	u, err := base.Parse(href)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil
	}
	u.Fragment, u.RawFragment, u.User = "", "", nil
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if u.RawQuery != "" {
		var keep []string
		for _, p := range strings.Split(u.RawQuery, "&") {
			k, _, _ := strings.Cut(p, "=")
			if p != "" && !trackingParam.MatchString(k) {
				keep = append(keep, p)
			}
		}
		u.RawQuery = strings.Join(keep, "&")
	}
	return u
}

// --- robots.txt (Google's reading: the most specific group, the longest rule, Allow wins a tie)

type robotsGroup struct {
	agents []string
	rules  []robotsRule
}

type robotsRule struct {
	allow bool
	path  string
	re    *regexp.Regexp
}

var robotsLine = regexp.MustCompile(`^([\w-]+)\s*:\s*(.*)$`)

func parseRobots(txt string) (groups []*robotsGroup, sitemaps []string) {
	var cur *robotsGroup
	lastAgent := false
	for _, raw := range strings.Split(txt, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		m := robotsLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		key, val := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		if key == "user-agent" {
			if cur == nil || !lastAgent {
				cur = &robotsGroup{}
				groups = append(groups, cur)
			}
			cur.agents = append(cur.agents, strings.ToLower(val))
			lastAgent = true
			continue
		}
		lastAgent = false
		switch {
		case key == "sitemap":
			sitemaps = append(sitemaps, val)
		case (key == "allow" || key == "disallow") && cur != nil && val != "":
			end := strings.HasSuffix(val, "$")
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(strings.TrimSuffix(val, "$")), `\*`, ".*")
			if end {
				pat += "$"
			}
			if re, err := regexp.Compile(pat); err == nil {
				cur.rules = append(cur.rules, robotsRule{allow: key == "allow", path: val, re: re})
			}
		}
	}
	return groups, sitemaps
}

func robotsBlocks(groups []*robotsGroup, agent, path string) string {
	best := ""
	var chosen []*robotsGroup
	for _, g := range groups {
		for _, a := range g.agents {
			if a != "*" && strings.Contains(agent, a) && len(a) > len(best) {
				best, chosen = a, nil
			}
			if a != "*" && a == best {
				chosen = append(chosen, g)
			}
		}
	}
	if best == "" {
		for _, g := range groups {
			for _, a := range g.agents {
				if a == "*" {
					chosen = append(chosen, g)
					break
				}
			}
		}
	}
	var win *robotsRule
	for _, g := range chosen {
		for i := range g.rules {
			r := &g.rules[i]
			if r.re.MatchString(path) && (win == nil || len(r.path) > len(win.path) || (len(r.path) == len(win.path) && r.allow)) {
				win = r
			}
		}
	}
	if win == nil || win.allow {
		return ""
	}
	return "Disallow: " + win.path
}

// --- the walk

type auditor struct {
	a        auditArgs
	start    *url.URL
	f        *auditFetcher
	pages    map[string]*auditPage
	order    []*auditPage
	queue    []*auditPage
	robots   []*robotsGroup
	fetched  int
	paramFed int
	stats    map[string]any
	deadline time.Time
}

var locTag = regexp.MustCompile(`(?is)<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</loc>`)

func (x *auditor) internal(u *url.URL) bool { return sameSite(u.Hostname(), x.start.Hostname()) }

// page returns the record for an address, making it on first sight and deciding
// then whether it will be fetched.
func (x *auditor) page(u *url.URL, depth int) *auditPage {
	key := u.String()
	if p, ok := x.pages[key]; ok {
		return p
	}
	p := &auditPage{URL: key, Depth: depth}
	x.pages[key] = p
	x.order = append(x.order, p)
	switch {
	case assetExt.MatchString(u.Path):
		p.Note = "a file, not a page: not fetched"
	case robotsBlocks(x.robots, "googlebot", u.RequestURI()) != "":
		p.Note = "robots.txt keeps Googlebot out (" + robotsBlocks(x.robots, "googlebot", u.RequestURI()) + "): not fetched"
	case u.RawQuery != "" && x.a.Params == "none":
		p.Note = "address with parameters: not fetched"
	case u.RawQuery != "" && x.a.Params != "all" && x.paramFed >= 50:
		p.Note = "address with parameters: not fetched (50 of them were, as a sample)"
	default:
		if u.RawQuery != "" {
			x.paramFed++
		}
		p.queued = true
		x.queue = append(x.queue, p)
	}
	return p
}

func (x *auditor) readSitemaps(listed []string) (urls []string, files []string, problems []string) {
	todo := listed
	if len(todo) == 0 {
		todo = []string{x.start.Scheme + "://" + x.start.Host + "/sitemap.xml"}
	}
	seen := map[string]bool{}
	for len(todo) > 0 && len(files) < 50 && len(urls) < 50000 {
		sm := todo[0]
		todo = todo[1:]
		u, err := url.Parse(strings.TrimSpace(sm))
		if err != nil || seen[sm] {
			continue
		}
		seen[sm] = true
		if !x.internal(u) {
			problems = append(problems, sm+" is on another host: not read")
			continue
		}
		r := x.f.get(u.String())
		for hop := 0; hop < 3 && r.status >= 300 && r.status < 400; hop++ {
			to, err := u.Parse(r.header.Get("Location"))
			if err != nil || !x.internal(to) {
				break
			}
			u = to
			r = x.f.get(u.String())
		}
		if r.status != 200 {
			if len(listed) > 0 {
				problems = append(problems, fmt.Sprintf("%s answers %d %s", sm, r.status, r.err))
			}
			continue
		}
		body := r.body
		if len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
			if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				body, _ = io.ReadAll(io.LimitReader(zr, 50<<20))
			}
		}
		files = append(files, sm)
		index := bytes.Contains(bytes.ToLower(body[:min(len(body), 2000)]), []byte("<sitemapindex"))
		for _, m := range locTag.FindAllSubmatch(body, -1) {
			loc := html.UnescapeString(string(m[1]))
			if index {
				todo = append(todo, loc)
			} else if len(urls) < 50000 {
				urls = append(urls, loc)
			}
		}
	}
	return urls, files, problems
}

func (x *auditor) take(p *auditPage, r auditResp) {
	x.fetched++
	p.Status, p.Ms, p.Bytes = r.status, r.ms, len(r.body)
	if r.err != "" {
		p.Note = "did not answer: " + r.err
		return
	}
	u, _ := url.Parse(p.URL)
	ct := strings.ToLower(r.header.Get("Content-Type"))
	p.Type, _, _ = strings.Cut(ct, ";")
	p.Robots = strings.ToLower(strings.Join(r.header.Values("X-Robots-Tag"), " "))
	if r.status >= 300 && r.status < 400 {
		if to := cleanURL(u, r.header.Get("Location")); to != nil {
			p.Redirect = to.String()
			if x.internal(to) {
				t := x.page(to, p.Depth)
				if t != p {
					t.Inlinks++
					if len(t.Refs) < auditRefs {
						t.Refs = append(t.Refs, p.URL+" (redirect)")
					}
				}
			}
		}
		return
	}
	if r.status != 200 || !(strings.Contains(ct, "html") || ct == "") {
		return
	}
	p.html = true
	f := readPage(r.body)
	p.Title, p.Desc, p.H1s, p.Lang, p.Hreflang, p.Words = f.title, f.desc, len(f.h1), f.lang, f.hreflang, f.words
	p.Images, p.NoAlt, p.Schema, p.hash, p.viewport = f.images, f.noAlt, f.schema, f.hash, f.viewport
	p.Robots = strings.TrimSpace(p.Robots + " " + f.robots)
	if len(f.h1) > 0 {
		p.H1 = f.h1[0]
	}
	base := u
	if f.base != "" {
		if b, err := u.Parse(f.base); err == nil {
			base = b
		}
	}
	if f.canonical != "" {
		if c := cleanURL(base, f.canonical); c != nil {
			p.Canonical = c.String()
		} else {
			p.Canonical = f.canonical
		}
	}
	once := map[string]bool{}
	for _, h := range f.links {
		to := cleanURL(base, h)
		if to == nil || once[to.String()] {
			continue
		}
		once[to.String()] = true
		if !x.internal(to) {
			p.External++
			continue
		}
		if to.String() == p.URL {
			continue
		}
		p.Links++
		if to.Scheme == "http" && u.Scheme == "https" {
			p.insecure++
		}
		t := x.page(to, p.Depth+1)
		t.Inlinks++
		if len(t.Refs) < auditRefs {
			t.Refs = append(t.Refs, p.URL)
		}
	}
}

func (x *auditor) walk(progress func(string)) {
	workers := min(max(x.a.Workers, 1), 8)
	last := time.Now()
	for len(x.queue) > 0 && x.fetched < x.a.MaxPages && time.Now().Before(x.deadline) {
		n := min(workers, len(x.queue), x.a.MaxPages-x.fetched)
		batch := x.queue[:n]
		x.queue = x.queue[n:]
		res := make([]auditResp, n)
		var wg sync.WaitGroup
		for i, p := range batch {
			wg.Add(1)
			go func(i int, u string) {
				defer wg.Done()
				res[i] = x.f.get(u)
			}(i, p.URL)
		}
		wg.Wait()
		for i, p := range batch {
			p.queued = false
			x.take(p, res[i])
		}
		if time.Since(last) > 20*time.Second {
			last = time.Now()
			progress(fmt.Sprintf("%d pages fetched, %d waiting, %d addresses seen", x.fetched, len(x.queue), len(x.pages)))
		}
	}
}

func noindex(robots string) bool {
	return strings.Contains(robots, "noindex") || strings.Contains(robots, "none")
}

// indexable: a page a search engine may list as it is.
func indexable(p *auditPage) bool {
	return p.Status == 200 && p.html && !noindex(p.Robots) && (p.Canonical == "" || p.Canonical == p.URL)
}

func short(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

func (x *auditor) issues(sitemapRead, complete bool) []auditIssue {
	var out []auditIssue
	add := func(id, sev, title, why string, items []auditItem) {
		if len(items) == 0 {
			return
		}
		is := auditIssue{ID: id, Title: title, Severity: sev, Why: why, Count: len(items)}
		is.Items = items[:min(len(items), auditPerIssue)]
		out = append(out, is)
	}
	from := func(p *auditPage) string {
		if len(p.Refs) == 0 {
			if p.Sitemap {
				return "listed in the sitemap"
			}
			return ""
		}
		return fmt.Sprintf("linked from %d page(s), first: %s", p.Inlinks, p.Refs[0])
	}
	pick := func(test func(p *auditPage) (bool, string)) []auditItem {
		var items []auditItem
		for _, p := range x.order {
			if ok, d := test(p); ok {
				items = append(items, auditItem{p.URL, d})
			}
		}
		return items
	}
	groups := func(key func(p *auditPage) string) []auditItem {
		by := map[string][]string{}
		for _, p := range x.order {
			if k := key(p); k != "" && indexable(p) {
				by[k] = append(by[k], p.URL)
			}
		}
		var items []auditItem
		for _, p := range x.order {
			if k := key(p); k != "" && indexable(p) && len(by[k]) > 1 {
				other := by[k][0]
				if other == p.URL {
					other = by[k][1]
				}
				items = append(items, auditItem{p.URL, fmt.Sprintf("%q, shared by %d pages, such as %s", short(k, 80), len(by[k]), other)})
			}
		}
		return items
	}

	add("broken_pages", "high", "Links to pages that do not exist", "Visitors and search engines land on an error page; fix the link or redirect the address.",
		pick(func(p *auditPage) (bool, string) {
			return p.Status >= 400 && p.Status < 500, fmt.Sprintf("answers %d; %s", p.Status, from(p))
		}))
	add("server_errors", "high", "Pages that fail with a server error", "The page is broken for everyone; the logs tool shows why.",
		pick(func(p *auditPage) (bool, string) {
			return p.Status >= 500 || (p.Status == 0 && strings.HasPrefix(p.Note, "did not answer")), strings.TrimSuffix(strings.TrimSpace(fmt.Sprintf("answers %d %s", p.Status, p.Note))+"; "+from(p), "; ")
		}))
	add("sitemap_not_ok", "high", "Sitemap lists addresses that redirect or fail", "A sitemap should only name pages that answer 200 and may be indexed; Google trusts it less otherwise.",
		pick(func(p *auditPage) (bool, string) {
			if !p.Sitemap || p.Status == 0 || p.Status == 200 {
				return false, ""
			}
			if p.Redirect != "" {
				return true, fmt.Sprintf("answers %d, redirects to %s", p.Status, p.Redirect)
			}
			return true, fmt.Sprintf("answers %d", p.Status)
		}))
	add("sitemap_noindex", "high", "Sitemap lists pages marked noindex or pointing elsewhere", "The sitemap says \"index this\" and the page says \"do not\": decide which is meant.",
		pick(func(p *auditPage) (bool, string) {
			if !p.Sitemap || p.Status != 200 || !p.html || indexable(p) {
				return false, ""
			}
			if noindex(p.Robots) {
				return true, "noindex"
			}
			return true, "canonical points to " + p.Canonical
		}))
	add("canonical_broken", "high", "Canonical points to a page that redirects or fails", "Google ignores a canonical it cannot follow and may pick the wrong address.",
		pick(func(p *auditPage) (bool, string) {
			if p.Canonical == "" || p.Canonical == p.URL {
				return false, ""
			}
			t := x.pages[p.Canonical]
			return t != nil && t.Status != 0 && t.Status != 200, fmt.Sprintf("canonical %s answers %d", p.Canonical, func() int {
				if t == nil {
					return 0
				}
				return t.Status
			}())
		}))
	add("redirect_chains", "medium", "Redirects that lead to another redirect", "Each extra hop slows visitors and wastes crawling; point the first address at the final one.",
		pick(func(p *auditPage) (bool, string) {
			if p.Redirect == "" {
				return false, ""
			}
			t := x.pages[p.Redirect]
			return t != nil && t.Redirect != "", fmt.Sprintf("%d to %s, which redirects again to %s", p.Status, p.Redirect, func() string {
				if t == nil {
					return ""
				}
				return t.Redirect
			}())
		}))
	add("links_to_redirects", "medium", "Internal links that point at a redirect", "The link works but takes a detour; link to the final address.",
		pick(func(p *auditPage) (bool, string) {
			real := 0
			for _, r := range p.Refs {
				if !strings.HasSuffix(r, " (redirect)") {
					real++
				}
			}
			return p.Redirect != "" && real > 0, fmt.Sprintf("%d to %s; %s", p.Status, p.Redirect, from(p))
		}))
	add("missing_title", "medium", "Pages without a title", "The title is the headline in search results.",
		pick(func(p *auditPage) (bool, string) { return indexable(p) && p.Title == "", "" }))
	add("duplicate_title", "medium", "Pages sharing the same title", "Search engines cannot tell the pages apart; each needs its own.", groups(func(p *auditPage) string { return p.Title }))
	add("missing_description", "low", "Pages without a meta description", "Google writes its own snippet, often a worse one.",
		pick(func(p *auditPage) (bool, string) { return indexable(p) && p.Desc == "", "" }))
	add("duplicate_description", "low", "Pages sharing the same meta description", "A description copied across pages says nothing about each.", groups(func(p *auditPage) string { return p.Desc }))
	add("missing_h1", "medium", "Pages without a main heading (h1)", "The h1 tells visitors and search engines what the page is about.",
		pick(func(p *auditPage) (bool, string) { return indexable(p) && (p.H1s == 0 || p.H1 == ""), "" }))
	add("multiple_h1", "low", "Pages with more than one h1", "Usually a theme mistake (logo or menu marked as h1).",
		pick(func(p *auditPage) (bool, string) {
			return indexable(p) && p.H1s > 1, fmt.Sprintf("%d h1 headings, first: %q", p.H1s, short(p.H1, 80))
		}))
	add("duplicate_content", "medium", "Different addresses serving the same text", "They compete with each other; keep one and point the others at it with a canonical or a redirect.", groups(func(p *auditPage) string { return p.hash }))
	add("thin_content", "low", "Pages with very little text", "Under 150 words of their own: often filter, tag or empty category pages that should not be indexed.",
		pick(func(p *auditPage) (bool, string) {
			return indexable(p) && p.Words < 150, fmt.Sprintf("%d words", p.Words)
		}))
	add("slow_pages", "medium", "Pages the server takes long to produce", "Over 2 seconds before the HTML is back, measured on the server itself; visitors wait longer.",
		pick(func(p *auditPage) (bool, string) {
			return p.Status == 200 && p.html && p.Ms > 2000, fmt.Sprintf("%d ms", p.Ms)
		}))
	add("title_length", "low", "Titles too long or too short", "Over 65 characters is cut off in results; under 15 says little.",
		pick(func(p *auditPage) (bool, string) {
			n := len([]rune(p.Title))
			return indexable(p) && p.Title != "" && (n > 65 || n < 15), fmt.Sprintf("%d characters: %q", n, short(p.Title, 90))
		}))
	add("description_length", "low", "Meta descriptions too long", "Over 165 characters is cut off in results.",
		pick(func(p *auditPage) (bool, string) {
			n := len([]rune(p.Desc))
			return indexable(p) && n > 165, fmt.Sprintf("%d characters", n)
		}))
	add("images_without_alt", "low", "Pages with images that have no alt text", "Alt text is what screen readers and image search read.",
		pick(func(p *auditPage) (bool, string) {
			return indexable(p) && p.NoAlt > 0, fmt.Sprintf("%d of %d images", p.NoAlt, p.Images)
		}))
	add("insecure_links", "low", "Pages linking to http:// addresses of this site", "Each such link goes through a redirect to https.",
		pick(func(p *auditPage) (bool, string) { return p.insecure > 0, fmt.Sprintf("%d links", p.insecure) }))
	add("deep_pages", "low", "Pages more than 4 clicks from the start page", "Pages buried deep are crawled less and found by fewer visitors.",
		pick(func(p *auditPage) (bool, string) {
			return indexable(p) && p.Depth > 4, fmt.Sprintf("%d clicks deep", p.Depth)
		}))
	add("no_viewport", "low", "Pages without a mobile viewport", "Without it phones show the desktop layout shrunk.",
		pick(func(p *auditPage) (bool, string) { return indexable(p) && !p.viewport, "" }))
	add("no_lang", "low", "Pages that do not say their language", "The lang attribute on <html> helps search engines and screen readers.",
		pick(func(p *auditPage) (bool, string) { return indexable(p) && p.Lang == "", "" }))
	add("noindex_pages", "low", "Pages kept out of search (noindex)", "Not a fault by itself: check that each is meant.",
		pick(func(p *auditPage) (bool, string) { return p.Status == 200 && p.html && noindex(p.Robots), from(p) }))
	add("canonical_elsewhere", "low", "Pages whose canonical names another address", "Not a fault by itself: these give their ranking to the other address. Check that each is meant.",
		pick(func(p *auditPage) (bool, string) {
			return p.Status == 200 && p.html && !noindex(p.Robots) && p.Canonical != "" && p.Canonical != p.URL, "canonical " + p.Canonical
		}))
	add("blocked_by_robots", "low", "Linked pages that robots.txt keeps Googlebot out of", "Fine for carts, search and filters; a problem when a page that should rank is on the list.",
		pick(func(p *auditPage) (bool, string) {
			return strings.HasPrefix(p.Note, "robots.txt"), strings.TrimSuffix(strings.TrimPrefix(p.Note, "robots.txt keeps Googlebot out ("), "): not fetched") + "; " + from(p)
		}))
	if sitemapRead {
		if complete {
			add("sitemap_only", "medium", "Pages only the sitemap names (no link leads to them)", "Without internal links a page ranks poorly and visitors cannot reach it.",
				pick(func(p *auditPage) (bool, string) {
					return p.Sitemap && p.Inlinks == 0 && p.Depth < 0 && (p.Status == 200 || p.Status == 0), ""
				}))
		}
		add("not_in_sitemap", "low", "Indexable pages missing from the sitemap", "The sitemap is how new and changed pages are found quickly.",
			pick(func(p *auditPage) (bool, string) { return indexable(p) && !p.Sitemap, "" }))
	}
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

func runAudit(a auditArgs, progress func(string)) (*auditRun, error) {
	start, err := auditStartURL(&a)
	if err != nil {
		return nil, err
	}
	if a.MaxPages <= 0 {
		a.MaxPages = 500
	}
	a.MaxPages = min(a.MaxPages, auditMaxPages)
	if a.Workers <= 0 {
		a.Workers = 3
	}
	if a.Minutes <= 0 || a.Minutes > 120 {
		a.Minutes = 45
	}
	f, err := newAuditFetcher(start, a.Via)
	if err != nil {
		return nil, err
	}
	began := time.Now()
	x := &auditor{a: a, start: start, f: f, pages: map[string]*auditPage{}, stats: map[string]any{}, deadline: began.Add(time.Duration(a.Minutes) * time.Minute)}
	progress("Fetching " + f.via + ".")

	var listed []string
	rb := f.get(start.Scheme + "://" + start.Host + "/robots.txt")
	switch {
	case rb.status == 200:
		x.robots, listed = parseRobots(string(rb.body))
		x.stats["robots_txt"] = "ok"
	case rb.status >= 500 || rb.err != "":
		x.stats["robots_txt"] = fmt.Sprintf("fails (%d %s): Google stops crawling a site whose robots.txt answers a server error", rb.status, rb.err)
	default:
		x.stats["robots_txt"] = fmt.Sprintf("answers %d: no rules, everything may be crawled", rb.status)
	}
	smURLs, smFiles, smProblems := x.readSitemaps(listed)
	x.stats["sitemaps"] = smFiles
	if len(smProblems) > 0 {
		x.stats["sitemap_problems"] = smProblems
	}

	x.page(start, 0)
	x.walk(progress)
	complete := len(x.queue) == 0
	inSitemap := 0
	for _, s := range smURLs {
		u := cleanURL(start, s)
		if u == nil || !x.internal(u) {
			continue
		}
		inSitemap++
		_, known := x.pages[u.String()]
		p := x.page(u, -1)
		p.Sitemap = true
		if !known && !p.queued && p.Note == "" {
			p.Note = "not fetched"
		}
	}
	x.stats["sitemap_urls"] = inSitemap
	if len(x.queue) > 0 {
		progress(fmt.Sprintf("Links followed: %d pages. Now the %d addresses only the sitemap names.", x.fetched, len(x.queue)))
		x.walk(progress)
	}
	for _, p := range x.queue {
		p.Note = "not fetched: the page limit or the time ran out"
	}

	byStatus := map[string]int{}
	byDepth := map[string]int{}
	var ms, htmlPages, canIndex int
	for _, p := range x.order {
		switch {
		case p.Status == 0:
			byStatus["not fetched"]++
		default:
			byStatus[fmt.Sprintf("%dxx", p.Status/100)]++
		}
		if p.Status == 200 && p.html {
			htmlPages++
			ms += p.Ms
			if indexable(p) {
				canIndex++
			}
			byDepth[strconv.Itoa(p.Depth)]++
		}
	}
	x.stats["addresses_seen"], x.stats["fetched"], x.stats["pages"], x.stats["indexable_pages"] = len(x.order), x.fetched, htmlPages, canIndex
	x.stats["by_status"], x.stats["pages_by_clicks_from_start"] = byStatus, byDepth
	if htmlPages > 0 {
		x.stats["average_ms"] = ms / htmlPages
	}
	if len(x.queue) > 0 {
		x.stats["incomplete"] = fmt.Sprintf("%d addresses were found and not fetched (limit %d pages, %d minutes). Run it again with a higher max_pages for the whole site.", len(x.queue), a.MaxPages, a.Minutes)
	}
	now := time.Now().UTC()
	return &auditRun{
		Run: now.Format("20060102-150405"), Host: strings.TrimPrefix(start.Hostname(), "www."), Start: start.String(),
		Started: began.UTC().Format(time.RFC3339), Finished: now.Format(time.RFC3339), Via: f.via,
		Stats: x.stats, Issues: x.issues(len(smFiles) > 0, complete && len(x.queue) == 0), Pages: x.order,
	}, nil
}

// --- keeping and asking (op audit_query)

func saveAudit(r *auditRun) error {
	dir := filepath.Join(auditDir, r.Host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	json.NewEncoder(zw).Encode(r)
	zw.Close()
	if err := os.WriteFile(filepath.Join(dir, r.Run+".json.gz"), buf.Bytes(), 0o600); err != nil {
		return err
	}
	runs := auditRuns(r.Host)
	for i := auditKeepRuns; i < len(runs); i++ {
		os.Remove(filepath.Join(dir, runs[i]+".json.gz"))
	}
	return nil
}

// auditRuns lists a host's kept runs, newest first.
func auditRuns(host string) []string {
	m, _ := filepath.Glob(filepath.Join(auditDir, host, "*.json.gz"))
	var out []string
	for _, f := range m {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".json.gz"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

func loadAudit(host, run string) (*auditRun, error) {
	if strings.ContainsAny(host+run, "/\\") || strings.Contains(host, "..") {
		return nil, errors.New("bad name")
	}
	f, err := os.Open(filepath.Join(auditDir, host, run+".json.gz"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var r auditRun
	if err := json.NewDecoder(zr).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func auditSummary(r *auditRun) map[string]any {
	issues := []map[string]any{}
	for _, is := range r.Issues {
		ex := []auditItem{}
		for i := 0; i < len(is.Items) && i < 3; i++ {
			ex = append(ex, is.Items[i])
		}
		issues = append(issues, map[string]any{"id": is.ID, "title": is.Title, "severity": is.Severity, "count": is.Count, "why": is.Why, "examples": ex})
	}
	return map[string]any{"run": r.Run, "host": r.Host, "start_url": r.Start, "started": r.Started, "finished": r.Finished, "fetched": r.Via, "stats": r.Stats, "issues": issues}
}

func auditQuery(raw json.RawMessage) (any, error) {
	var a struct {
		Site   string `json:"site"`
		URL    string `json:"url"`
		Run    string `json:"run"`
		Issue  string `json:"issue"`
		Page   string `json:"page"`
		Match  string `json:"match"`
		Status string `json:"status"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}
	json.Unmarshal(raw, &a)
	hosts := []string{}
	if entries, err := os.ReadDir(auditDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && len(auditRuns(e.Name())) > 0 {
				hosts = append(hosts, e.Name())
			}
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("no site audit has been run on this server yet; start one with site_audit")
	}
	host := ""
	switch {
	case a.URL != "" || a.Site != "":
		args := auditArgs{URL: a.URL, Site: a.Site}
		u, err := auditStartURL(&args)
		if err != nil {
			return nil, err
		}
		host = strings.TrimPrefix(u.Hostname(), "www.")
	case len(hosts) == 1:
		host = hosts[0]
	default:
		return nil, fmt.Errorf("audits are kept for %s: say which with url", strings.Join(hosts, ", "))
	}
	runs := auditRuns(host)
	if len(runs) == 0 {
		return nil, fmt.Errorf("no audit kept for %s (kept: %s)", host, strings.Join(hosts, ", "))
	}
	run := runs[0]
	if a.Run != "" {
		run = a.Run
	}
	r, err := loadAudit(host, run)
	if err != nil {
		return nil, fmt.Errorf("no run %s for %s (kept: %s)", run, host, strings.Join(runs, ", "))
	}
	if a.Limit <= 0 {
		a.Limit = 50
	}
	a.Limit = min(a.Limit, 200)
	a.Offset = max(a.Offset, 0)
	window := func(n int) (int, int, any) {
		lo := min(a.Offset, n)
		hi := min(lo+a.Limit, n)
		if hi < n {
			return lo, hi, hi
		}
		return lo, hi, nil
	}
	switch {
	case a.Page != "":
		want := a.Page
		if u := cleanURL(&url.URL{Scheme: "https", Host: host}, a.Page); u != nil {
			want = u.String()
		}
		for _, p := range r.Pages {
			if p.URL == want || p.URL == a.Page {
				var in []string
				for _, is := range r.Issues {
					for _, it := range is.Items {
						if it.URL == p.URL {
							in = append(in, is.ID)
							break
						}
					}
				}
				return map[string]any{"run": r.Run, "page": p, "issues": in}, nil
			}
		}
		return nil, fmt.Errorf("%s was not seen in run %s", a.Page, r.Run)
	case a.Issue != "":
		for _, is := range r.Issues {
			if is.ID == a.Issue {
				lo, hi, next := window(len(is.Items))
				return map[string]any{"run": r.Run, "issue": is.ID, "title": is.Title, "severity": is.Severity, "why": is.Why, "count": is.Count, "offset": lo, "items": is.Items[lo:hi], "next_offset": next}, nil
			}
		}
		ids := []string{}
		for _, is := range r.Issues {
			ids = append(ids, is.ID)
		}
		return nil, fmt.Errorf("run %s has no issue %q; it has: %s", r.Run, a.Issue, strings.Join(ids, ", "))
	case a.Match != "" || a.Status != "":
		var hit []*auditPage
		for _, p := range r.Pages {
			if a.Match != "" && !strings.Contains(p.URL, a.Match) {
				continue
			}
			if a.Status != "" && a.Status != strconv.Itoa(p.Status) && !strings.EqualFold(a.Status, fmt.Sprintf("%dxx", p.Status/100)) {
				continue
			}
			hit = append(hit, p)
		}
		lo, hi, next := window(len(hit))
		return map[string]any{"run": r.Run, "count": len(hit), "offset": lo, "pages": hit[lo:hi], "next_offset": next}, nil
	}
	out := auditSummary(r)
	out["runs_kept"] = runs
	// Against the run before: what got better or worse.
	if a.Run == "" && len(runs) > 1 {
		if prev, err := loadAudit(host, runs[1]); err == nil {
			was := map[string]int{}
			for _, is := range prev.Issues {
				was[is.ID] = is.Count
			}
			change := map[string]string{}
			for _, is := range r.Issues {
				if was[is.ID] != is.Count {
					change[is.ID] = fmt.Sprintf("%d, was %d", is.Count, was[is.ID])
				}
				delete(was, is.ID)
			}
			for id, n := range was {
				change[id] = fmt.Sprintf("0, was %d", n)
			}
			out["since_run_"+prev.Run] = change
		}
	}
	out["next"] = "Pass issue (an id above) for the pages behind it, page for everything about one address, or match / status to list pages."
	return out, nil
}

// siteAuditNow is the background job: it prints progress, keeps the run and
// ends with the summary as JSON.
func siteAuditNow(argsFile string) error {
	b, err := os.ReadFile(argsFile)
	if err != nil {
		return err
	}
	os.Remove(argsFile)
	var a auditArgs
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	r, err := runAudit(a, func(s string) { fmt.Println(s) })
	if err != nil {
		return err
	}
	if err := saveAudit(r); err != nil {
		return err
	}
	// Old runs of sites no longer looked at go after 90 days.
	if all, _ := filepath.Glob(filepath.Join(auditDir, "*", "*.json.gz")); len(all) > 0 {
		for _, f := range all {
			if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) > 90*24*time.Hour {
				os.Remove(f)
			}
		}
	}
	j, _ := json.MarshalIndent(auditSummary(r), "", " ")
	fmt.Println(string(j))
	return nil
}
