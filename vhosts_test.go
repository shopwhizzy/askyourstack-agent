package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A server laid out like a hosting panel: nothing under /var/www or /home,
// the web server's configuration is the only map.
func panel(t *testing.T) string {
	d := t.TempDir()
	// Magento the way its sample configuration serves it: root in a variable, pub as document root.
	put(t, d+"/data/shop/app/etc/env.php", "<?php return [];")
	put(t, d+"/data/shop/nginx.conf.sample", "root $MAGE_ROOT/pub;\nlocation ~ ^/(a|b){2}$ { deny all; }\n")
	// WordPress with nginx in front of Apache, as Plesk does.
	put(t, d+"/vhosts/blog.example.com/httpdocs/wp-config.php", "<?php define('DB_NAME', 'blog'); define( \"DB_USER\", 'u' ); $table_prefix = 'bl_';")
	put(t, d+"/vhosts/blog.example.com/httpdocs/wp-load.php", "<?php")
	// WordPress with its configuration one folder above the install.
	put(t, d+"/apps/news/wp-config.php", "<?php define('DB_NAME', 'news');")
	put(t, d+"/apps/news/public/wp-load.php", "<?php")
	// A folder the web server serves that holds no site.
	put(t, d+"/static/index.html", "hello")

	put(t, d+"/nginx/nginx.conf", "# main\nhttp {\n  include conf.d/*.conf; # the sites\n  include "+d+"/nginx/missing/*.conf;\n}\n")
	put(t, d+"/nginx/conf.d/shop.conf", `
upstream fastcgi_backend { server unix:/run/php-fpm/shop.sock; }
server {
  listen 443 ssl;
  server_name shop.example.com www.shop.example.com _;
  set $MAGE_ROOT `+d+`/data/shop;
  access_log `+d+`/logs/shop.access.log main;
  include `+d+`/data/shop/nginx.conf.sample;
}
server { listen 80; server_name shop.example.com; return 301 https://$host$request_uri; }
`)
	put(t, d+"/nginx/conf.d/plesk.conf", `
server {
  server_name blog.example.com *.blog.example.com;
  root "`+d+`/vhosts/blog.example.com/httpdocs";
  access_log "`+d+`/logs/blog.proxy_access_ssl_log";
  location /x { access_log off; root `+d+`/static; }
}
server { server_name files.example.com; root `+d+`/static; access_log syslog:server=1.2.3.4; }
`)
	put(t, d+"/apache/conf/httpd.conf", "ServerRoot \"/etc/httpd\"\nIncludeOptional conf.d/*.conf\n")
	put(t, d+"/apache/conf.d/sites.conf", `
<VirtualHost 127.0.0.1:7080>
  ServerName blog.example.com:443
  ServerAlias www.blog.example.com
  DocumentRoot "`+d+`/vhosts/blog.example.com/httpdocs"
  CustomLog `+d+`/logs/blog.access_ssl_log plesklog
</VirtualHost>
<VirtualHost *:80>
  ServerName news.example.com
  DocumentRoot `+d+`/apps/news/public
  CustomLog logs/news_access.log combined
  CustomLog "|/usr/bin/rotatelogs /x 86400" combined
</VirtualHost>
`)
	nginxConfs, apacheConfs = []string{d + "/nginx/nginx.conf"}, []string{d + "/apache/conf/httpd.conf"}
	vhostCache.at = time.Time{}
	t.Cleanup(func() { vhostCache.at = time.Time{} })
	return d
}

func TestSitesFromVhosts(t *testing.T) {
	d := panel(t)
	got := map[string]*site{}
	for _, s := range findSites() {
		got[s.Root] = s
	}
	shop, blog, news := got[d+"/data/shop"], got[d+"/vhosts/blog.example.com/httpdocs"], got[d+"/apps/news/public"]
	if shop == nil || blog == nil || news == nil || len(got) != 3 {
		t.Fatalf("sites found: %v", reflect.ValueOf(got).MapKeys())
	}
	if shop.Kind != "magento" || !reflect.DeepEqual(shop.Domains, []string{"shop.example.com", "www.shop.example.com"}) || !reflect.DeepEqual(shop.AccessLogs, []string{d + "/logs/shop.access.log"}) {
		t.Errorf("shop: %+v", shop)
	}
	// nginx is in front of Apache for the blog: only nginx's log counts.
	if blog.Kind != "wordpress" || !reflect.DeepEqual(blog.Domains, []string{"blog.example.com", "www.blog.example.com"}) || !reflect.DeepEqual(blog.AccessLogs, []string{d + "/logs/blog.proxy_access_ssl_log"}) {
		t.Errorf("blog: %+v", blog)
	}
	if blog.DBName != "blog" || blog.Prefix != "bl_" {
		t.Errorf("blog database: %q %q", blog.DBName, blog.Prefix)
	}
	// The install is in public, its configuration one folder up; a relative Apache log sits under the server root.
	if news.Kind != "wordpress" || news.DBName != "news" || !reflect.DeepEqual(news.AccessLogs, []string{d + "/apache/logs/news_access.log"}) {
		t.Errorf("news: %+v", news)
	}
}

func TestPickSite(t *testing.T) {
	d := panel(t)
	for ref, want := range map[string]string{
		d + "/data/shop/":               d + "/data/shop",
		"shop.example.com":              d + "/data/shop",
		"https://www.BLOG.example.com/": d + "/vhosts/blog.example.com/httpdocs",
		"news.example.com":              d + "/apps/news/public",
	} {
		s, err := pickSite(ref)
		if err != nil || s.Root != want {
			t.Errorf("pickSite(%q) = %v, %v; want %s", ref, s, err, want)
		}
	}
	// A site no configuration points at still works when its root is given.
	put(t, d+"/elsewhere/wp/wp-config.php", "<?php define('DB_NAME', 'x');")
	if s, err := pickSite(d + "/elsewhere/wp"); err != nil || s.Kind != "wordpress" || s.DBName != "x" {
		t.Errorf("explicit root: %v, %v", s, err)
	}
	for _, ref := range []string{d + "/static", "files.example.com", "nothing.example.org"} {
		if s, err := pickSite(ref); err == nil {
			t.Errorf("pickSite(%q) found %v", ref, s.Root)
		}
	}
}

func TestAccessLogGlobs(t *testing.T) {
	d := panel(t)
	got := accessLogGlobs()[len(logGlobs):]
	want := []string{d + "/logs/blog.proxy_access_ssl_log", d + "/logs/shop.access.log", d + "/apache/logs/news_access.log"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logs from virtual hosts:\n got %v\nwant %v", got, want)
	}
}

func TestHostName(t *testing.T) {
	for in, want := range map[string]string{"Shop.Example.com": "shop.example.com", "example.com:443": "example.com", "https://example.com/shop?a=1": "example.com", "_": "", "*.example.com": "", "~^www\\d+\\.example\\.com$": "", "localhost": "", "$host": "", ".example.com": ""} {
		if got := hostName(in); got != want {
			t.Errorf("hostName(%q) = %q, want %q", in, got, want)
		}
	}
}
