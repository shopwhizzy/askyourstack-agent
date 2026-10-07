package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestReadPage(t *testing.T) {
	f := readPage([]byte(`<!doctype html><html lang="pt"><head><title> Shop &amp; more </title>
<meta name="description" content="All about it">
<meta name="robots" content="NOINDEX, follow"><link rel="canonical" href="/a?utm_source=x">
<link rel="alternate" hreflang="en" href="/en/"><meta name="viewport" content="width=device-width">
<script type="application/ld+json">{"@graph":[{"@type":"Product"},{"@type":["Organization","Store"]}]}</script>
<script>var a = "<a href='/not-a-link'>";</script></head>
<body><header><a href="/menu">Menu words here</a></header>
<h1><span>Main</span> heading</h1><h1></h1>
<div x-data="{ open: 1 > 0 }" class="x"><a href="/b">B</a> <a href='#top'>top</a> <a href="mailto:x@y.z">mail</a></div>
<img src="a.png"><img src="b.png" alt="">
<!-- <a href="/commented"> -->
<p>one two three</p><footer>footer words</footer></body></html>`))
	if f.title != "Shop & more" || f.desc != "All about it" || f.lang != "pt" || !f.viewport || f.hreflang != 1 {
		t.Fatalf("head: %+v", f)
	}
	if !noindex(f.robots) || f.canonical != "/a?utm_source=x" {
		t.Fatalf("robots %q canonical %q", f.robots, f.canonical)
	}
	if len(f.h1) != 1 || f.h1[0] != "Main heading" {
		t.Fatalf("h1: %q", f.h1)
	}
	if got := strings.Join(f.links, " "); got != "/menu /b #top mailto:x@y.z" {
		t.Fatalf("links: %q", got)
	}
	if f.images != 2 || f.noAlt != 1 {
		t.Fatalf("images %d without alt %d", f.images, f.noAlt)
	}
	if strings.Join(f.schema, ",") != "Product,Organization,Store" {
		t.Fatalf("schema: %v", f.schema)
	}
	// The page's own words: the header and footer are left out.
	if f.words != 8 {
		t.Fatalf("words: %d", f.words)
	}
}

func TestCleanURL(t *testing.T) {
	base, _ := url.Parse("https://www.Example.com/shop/page.html?x=1")
	for in, want := range map[string]string{
		"../a#frag":                       "https://www.example.com/a",
		"?utm_source=n&color=red&gclid=1": "https://www.example.com/shop/page.html?color=red",
		"//EXAMPLE.com:443/x":             "https://example.com/x",
		"http://example.com":              "http://example.com/",
		"javascript:void(0)":              "",
		"mailto:a@b.c":                    "",
		"#top":                            "",
	} {
		got := ""
		if u := cleanURL(base, in); u != nil {
			got = u.String()
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestRobotsRules(t *testing.T) {
	g, sm := parseRobots("User-agent: *\nDisallow: /private/\nAllow: /private/open\nDisallow: /*?sort=\nDisallow: /end$\n\nUser-agent: Googlebot\nDisallow: /g/\nSitemap: https://x.test/sitemap.xml\n")
	if len(sm) != 1 {
		t.Fatalf("sitemaps: %v", sm)
	}
	for path, blocked := range map[string]bool{"/private/x": true, "/private/open/y": false, "/list?sort=price": true, "/end": true, "/endless": false, "/g/x": false} {
		if got := robotsBlocks(g, "bingbot", path) != ""; got != blocked {
			t.Errorf("* %s: blocked %v, want %v", path, got, blocked)
		}
	}
	// Googlebot has its own group and follows only that one.
	if robotsBlocks(g, "googlebot", "/g/x") == "" || robotsBlocks(g, "googlebot", "/private/x") != "" {
		t.Error("the Googlebot group should win over *")
	}
}

func TestAuditWalk(t *testing.T) {
	page := func(title, body string) string {
		return `<html lang="en"><head><title>` + title + `</title><meta name="description" content="d ` + title + `"><meta name="viewport" content="w"></head><body><h1>` + title + `</h1>` + body + strings.Repeat(" word", 200) + `</body></html>`
	}
	mux := http.NewServeMux()
	var srv *httptest.Server
	html := func(path, doc string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, doc)
		})
	}
	html("/", page("Home page of the test shop", `<a href="/a">a</a> <a href="/b?utm_source=x">b</a> <a href="/gone">gone</a> <a href="/old">old</a> <a href="/secret/x">s</a> <a href="/img.png">i</a> <a href="https://other.test/">o</a> <a href="/hidden">h</a> <a href="/c">c</a>`))
	html("/a", page("Same title on two pages here", `<a href="/">home</a>`))
	html("/b", page("Same title on two pages here", `<a href="/boom">boom</a>`))
	html("/c", `<html><head></head><body>short</body></html>`)
	html("/hidden", strings.Replace(page("Hidden page kept out of search", ""), "<head>", `<head><meta name="robots" content="noindex">`, 1))
	html("/orphan", page("Only the sitemap knows this one", ""))
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/older", 301) })
	mux.HandleFunc("/older", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/a", 302) })
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "broken", 500) })
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nDisallow: /secret/\nSitemap: %s/map.xml\n", srv.URL)
	})
	mux.HandleFunc("/map.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<urlset><url><loc>%[1]s/</loc></url><url><loc>%[1]s/a</loc></url><url><loc>%[1]s/orphan</loc></url><url><loc>%[1]s/hidden</loc></url><url><loc>%[1]s/old</loc></url></urlset>`, srv.URL)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	r, err := runAudit(auditArgs{URL: srv.URL + "/", Via: "public", MaxPages: 100}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, is := range r.Issues {
		for _, it := range is.Items {
			got[is.ID] = append(got[is.ID], strings.TrimPrefix(it.URL, srv.URL))
		}
	}
	want := map[string]string{
		"broken_pages": "/gone", "server_errors": "/boom", "redirect_chains": "/old", "links_to_redirects": "/old",
		"duplicate_title": "/a /b", "sitemap_not_ok": "/old", "sitemap_noindex": "/hidden", "noindex_pages": "/hidden",
		"sitemap_only": "/orphan", "blocked_by_robots": "/secret/x", "missing_title": "/c", "missing_h1": "/c", "thin_content": "/c",
		"not_in_sitemap": "/b /c",
	}
	for id, w := range want {
		if strings.Join(got[id], " ") != w {
			t.Errorf("%s: got %v, want %s", id, got[id], w)
		}
	}
	for _, id := range []string{"canonical_broken", "slow_pages", "missing_description"} {
		if len(got[id]) > 0 && id != "missing_description" || id == "missing_description" && strings.Join(got[id], " ") != "/c" {
			t.Errorf("%s should be empty: %v", id, got[id])
		}
	}
	if r.Stats["sitemap_urls"] != 5 || r.Stats["robots_txt"] != "ok" {
		t.Errorf("stats: %v", r.Stats)
	}
	// Keeping it and asking by issue.
	auditDir = t.TempDir()
	if err := saveAudit(r); err != nil {
		t.Fatal(err)
	}
	ask := func(q map[string]any) map[string]any {
		b, _ := json.Marshal(q)
		out, err := auditQuery(b)
		if err != nil {
			t.Fatalf("%v: %v", q, err)
		}
		return out.(map[string]any)
	}
	if s := ask(map[string]any{}); s["host"] != r.Host || len(s["issues"].([]map[string]any)) != len(r.Issues) {
		t.Errorf("summary: %v", s)
	}
	if s := ask(map[string]any{"issue": "broken_pages"}); s["count"] != 1 || !strings.Contains(s["items"].([]auditItem)[0].Detail, "linked from 1 page") {
		t.Errorf("issue: %v", s)
	}
	if s := ask(map[string]any{"page": srv.URL + "/old"}); s["page"].(*auditPage).Redirect != srv.URL+"/older" {
		t.Errorf("page: %v", s)
	}
	if s := ask(map[string]any{"status": "3xx"}); s["count"] != 2 {
		t.Errorf("status filter: %v", s["count"])
	}
}

// The fake sites in these tests listen on loopback, which the audit otherwise refuses.
func init() { auditAllowInternal = true }
