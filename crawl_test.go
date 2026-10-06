package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCrawlReport(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 21, 0, 0, 0, time.UTC)
	line := func(ip string, ago time.Duration, path, status, agent string) string {
		return fmt.Sprintf("%s - - [%s] \"GET %s HTTP/1.1\" %s 100 \"-\" \"%s\"\n", ip, now.Add(-ago).Format("02/Jan/2006:15:04:05 -0700"), path, status, agent)
	}
	g := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	var b strings.Builder
	b.WriteString(line("66.249.66.1", 30*time.Hour, "/too-old", "200", g)) // outside 24 h
	for i := 0; i < 40; i++ {
		b.WriteString(line("66.249.66.1", time.Duration(i)*time.Minute, fmt.Sprintf("/women/tops.html?color=%d&size=2", i), "200", g))
	}
	for i := 0; i < 5; i++ {
		b.WriteString(line("66.249.66.1", 2*time.Hour, "/gone.html", "404", g))
	}
	b.WriteString(line("66.249.66.1", 3*time.Hour, "/old", "301", g))
	b.WriteString(line("6.6.6.6", time.Hour, "/", "200", g)) // claims to be Google
	b.WriteString(line("1.2.3.4", time.Hour, "/", "200", "Mozilla/5.0 (Windows NT 10.0) Chrome/120"))
	b.WriteString(line("1.2.3.5", time.Hour, "/x", "200", "GPTBot/1.2"))
	log := filepath.Join(dir, "access.log")
	os.WriteFile(log, []byte(b.String()), 0o644)
	os.Chtimes(log, now, now)

	verify := func(name, ip string) bool { return strings.HasPrefix(ip, "66.249.") }
	got, err := crawlAt(now, []string{log}, 24, verify)
	if err != nil {
		t.Fatal(err)
	}
	r := got.(map[string]any)
	if r["requests"] != 49 || r["not_crawlers"] != 1 {
		t.Fatalf("requests %v, humans %v", r["requests"], r["not_crawlers"])
	}
	gb := r["crawlers"].(map[string]any)["Googlebot"].(*crawlStats)
	if gb.Hits != 47 || gb.Classes["filtered"] != 40 || gb.Statuses["404"] != 5 || gb.Statuses["3xx"] != 1 {
		t.Errorf("googlebot %+v", gb)
	}
	if gb.NotFound[0].Key != "/gone.html" || gb.NotFound[0].N != 5 {
		t.Errorf("404s %v", gb.NotFound)
	}
	if gb.Verified.Genuine != 46 || gb.Verified.Fake != 1 || gb.Verified.FakeIPs[0] != "6.6.6.6" {
		t.Errorf("verified %+v", gb.Verified)
	}
	if gb.Hourly[23] != 40 {
		t.Errorf("hourly %v", gb.Hourly)
	}
	if _, ok := r["crawlers"].(map[string]any)["GPTBot"]; !ok {
		t.Error("GPTBot missing")
	}
	if _, err := crawlAt(now, []string{filepath.Join(dir, "none*.log")}, 24, verify); err == nil {
		t.Error("no logs should be an error")
	}
}
