package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPathClass(t *testing.T) {
	cases := map[string]string{
		"/catalogsearch/result/?q=shoes":                 "search",
		"/customer/account/loginPost/":                   "login",
		"/customer/account/createpost/":                  "signup",
		"/customer/account/forgotpasswordpost/":          "password_reset",
		"/women/tops.html?color=49&size=167&price=10-20": "filtered",
		"/women/tops.html?p=2":                           "pages",
		"/static/version1/frontend/x.js":                 "static",
		"/static/version1/frontend/Magento/luma/en_US/Magento_Ui/templates/collection.html": "static",
		"/static/version1/frontend/Magento/luma/en_US/js-translation.json":                  "static",
		"/pub/media/catalog/product/a/b/ab.jpg?width=300":                                   "static",
		"/women/tops.html":                "pages",
		"/wp-content/plugins/x/shell.php": "pages",
		"/rest/V1/guest-carts":            "api",
		"/wp-login.php":                   "login",
		"/?s=hello":                       "search",
		"/checkout/cart/add/":             "cart_checkout",
	}
	for p, want := range cases {
		if got := pathClass(p); got != want {
			t.Errorf("%s: got %s, want %s", p, got, want)
		}
	}
}

func TestTraffic(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 21, 0, 30, 0, time.UTC)
	var b strings.Builder
	// A quiet hour before, then a flood on search from many IPs in the last 3 minutes.
	for i := 0; i < 60; i++ {
		at := now.Add(-time.Duration(30-i/4) * time.Minute)
		fmt.Fprintf(&b, "10.0.0.%d - - [%s] \"GET /women.html HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n", i%9, at.Format("02/Jan/2006:15:04:05 -0700"))
	}
	for i := 0; i < 3000; i++ {
		at := now.Add(-time.Duration(i%180) * time.Second)
		fmt.Fprintf(&b, "203.0.%d.%d - - [%s] \"GET /catalogsearch/result/?q=x%d HTTP/1.1\" 200 9000 \"-\" \"python-requests/2.31\"\n", i%50, i%200, at.Format("02/Jan/2006:15:04:05 -0700"), i)
	}
	// One visitor's page with its 40 scripts and images, and Varnish handing the
	// same page on to the backend from this machine: neither is a flood.
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "198.51.100.7 - - [%s] \"GET /static/frontend/x/%d.js HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n", now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700"), i)
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "127.0.0.1 - - [%s] \"GET /checkout/ HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n", now.Add(-time.Minute).Format("02/Jan/2006:15:04:05 -0700"))
	}
	log := filepath.Join(dir, "access.log")
	os.WriteFile(log, []byte(b.String()), 0o644)
	os.Chtimes(log, now, now)
	got, err := trafficAt(now, []string{filepath.Join(dir, "*.log")})
	if err != nil {
		t.Fatal(err)
	}
	r := got.(map[string]any)
	if r["last5"].(int) != 3040 || r["pages5"].(int) != 3000 || r["own_hops"].(int) != 500 {
		t.Errorf("last5 = %v, pages5 = %v, own_hops = %v", r["last5"], r["pages5"], r["own_hops"])
	}
	if c := r["classes"].(map[string]int); c["search"] != 3000 {
		t.Errorf("classes = %v", c)
	}
	if r["ips"].(int) < 200 {
		t.Errorf("ips = %v", r["ips"])
	}
	m := r["minutes"].([]int)
	sum := 0
	for _, n := range m {
		sum += n
	}
	if sum < 3040 || m[14]+m[13]+m[12]+m[11] < 3000 {
		t.Errorf("minutes = %v", m)
	}
	if a := r["top_agents"].([]counted); a[0].Key != "python-requests/2.31" {
		t.Errorf("agents = %v", a)
	}
}
