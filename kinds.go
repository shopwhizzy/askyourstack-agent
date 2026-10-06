package main

// The kinds of site the agent knows. Each entry says how to recognise one, read
// its version and database settings from its own configuration, find its
// address, run its command line tool, tell whether its scheduler is alive, and
// which folders are for uploads (PHP there is suspect). A new kind is one more
// entry here, a test with a sample configuration, and a playbook on the hub.

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type siteKindDef struct {
	Name    string
	Label   string
	At      func(dir string) string          // the site's root when dir (a folder, often the one the web server serves) holds or belongs to one
	Version func(root string) string         // from the code, no database
	DB      func(s *site) *dbConf            // nil when it cannot be read or is not MySQL/MariaDB
	Console func(s *site) ([]string, string) // its command line tool as argv, or why there is none
	Address func(s *site) string
	CronSQL func(s *site) string // one number: minutes since its scheduler last finished a job
	WebRoot string               // the folder served, relative to the root ("" = the root)
	Uploads []string             // folders for uploaded files, relative, with a trailing slash
	Skip    []string             // caches and compiled code the malware scan leaves alone
	Logs    []string             // its own log files, relative globs
}

var kinds []*siteKindDef

func kindOf(name string) *siteKindDef {
	for _, k := range kinds {
		if k.Name == name {
			return k
		}
	}
	return nil
}

func kindNames() string {
	var n []string
	for _, k := range kinds {
		n = append(n, k.Label)
	}
	return strings.Join(n, ", ")
}

// siteAt says which kind of site a folder holds or belongs to, and its root.
// Only sites whose configuration the agent can read count.
func siteAt(dir string) (*siteKindDef, string) {
	for _, k := range kinds {
		if root := k.At(dir); root != "" {
			return k, root
		}
	}
	return nil, ""
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func here(ok bool, dir string) string {
	if ok {
		return dir
	}
	return ""
}

// --- reading configuration without running it

func fileText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4<<20 {
		return ""
	}
	return string(b)
}

func firstMatch(text, pattern string) string {
	if m := regexp.MustCompile(pattern).FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

var phpString = `(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")`

func phpUnquote(single, double string) string {
	if single != "" {
		return strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(single)
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`).Replace(double)
}

var phpDefineRe = regexp.MustCompile(`define\(\s*['"]([A-Z_0-9]+)['"]\s*,\s*` + phpString + `\s*\)`)

// phpDefines: define('NAME', 'value') lines with a plain string value.
func phpDefines(text string) map[string]string {
	out := map[string]string{}
	for _, m := range phpDefineRe.FindAllStringSubmatch(text, -1) {
		out[m[1]] = phpUnquote(m[2], m[3])
	}
	return out
}

var phpPairRe = regexp.MustCompile(`['"]([a-z_]+)['"]\s*=>\s*(?:` + phpString + `|(\d+)|(null|NULL))`)

// phpPairs: 'key' => 'value' entries of a PHP array, plain strings and numbers only.
func phpPairs(text string) map[string]string {
	out := map[string]string{}
	for _, m := range phpPairRe.FindAllStringSubmatch(text, -1) {
		if _, dup := out[m[1]]; dup {
			continue
		}
		if m[4] != "" {
			out[m[1]] = m[4]
		} else {
			out[m[1]] = phpUnquote(m[2], m[3])
		}
	}
	return out
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// dotenv reads KEY=value files, later files winning, then lets real environment
// variables (a container's) win over all of them, as the frameworks do.
func dotenv(env map[string]string, paths ...string) map[string]string {
	out := map[string]string{}
	for _, p := range paths {
		for _, line := range strings.Split(fileText(p), "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
			k, v, ok := strings.Cut(line, "=")
			k = strings.TrimSpace(k)
			if !ok || k == "" || strings.HasPrefix(k, "#") {
				continue
			}
			v = strings.TrimSpace(v)
			switch {
			case len(v) >= 2 && v[0] == '"':
				if e := strings.LastIndex(v, `"`); e > 0 {
					v = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(v[1:e])
				}
			case len(v) >= 2 && v[0] == '\'':
				if e := strings.LastIndex(v, `'`); e > 0 {
					v = v[1:e]
				}
			default:
				if i := strings.Index(v, " #"); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
			}
			out[k] = v
		}
	}
	for k, v := range env {
		out[k] = v
	}
	for k, v := range out {
		out[k] = envRef.ReplaceAllStringFunc(v, func(ref string) string { return out[envRef.FindStringSubmatch(ref)[1]] })
	}
	return out
}

// dbFromURL reads mysql://user:password@host:3306/name.
func dbFromURL(raw string) *dbConf {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || !(strings.HasPrefix(u.Scheme, "mysql") || strings.HasPrefix(u.Scheme, "mariadb")) {
		return nil
	}
	c := &dbConf{Name: strings.Trim(u.Path, "/"), Host: u.Hostname(), Port: u.Port()}
	if u.User != nil {
		c.User = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	return c
}

func mysqlKind(driver string) bool {
	d := strings.ToLower(driver)
	return d == "" || strings.Contains(d, "mysql") || strings.Contains(d, "mariadb")
}

func hostConf(name, user, password, host, port, prefix string) *dbConf {
	if name == "" {
		return nil
	}
	c := &dbConf{Name: name, User: user, Password: password, Prefix: prefix}
	if host == "" {
		host = "localhost"
	}
	splitHost(c, host)
	if port != "" && c.Port == "" && c.Socket == "" {
		c.Port = port
	}
	return c
}

// sqlValue asks the site's database for one value.
func sqlValue(s *site, sql string) string {
	if s.db == nil || s.db.Name == "" {
		return ""
	}
	b, _ := json.Marshal(map[string]any{"site": s.Root, "sql": sql, "read_only": true, "max_rows": 1})
	res, err := dbQuery(b)
	if err != nil {
		return ""
	}
	if rows := res.(map[string]any)["rows"].([][]string); len(rows) == 1 && len(rows[0]) >= 1 && rows[0][0] != "NULL" {
		return rows[0][0]
	}
	return ""
}

func fromDomain(s *site) string {
	if len(s.Domains) > 0 {
		return "https://" + s.Domains[0] + "/"
	}
	return ""
}

// webAddress keeps a value only when it is an address the outside world could
// open: not localhost or a private address, which a site in a container or
// behind a proxy often has as its own idea of where it lives.
func webAddress(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return ""
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return ""
	}
	return strings.TrimSpace(v)
}

func noConsole(why string) func(*site) ([]string, string) {
	return func(*site) ([]string, string) { return nil, why }
}

// --- the kinds

var drupalDB = regexp.MustCompile(`(?s)\$databases\s*\[\s*['"]default['"]\s*\]\s*\[\s*['"]default['"]\s*\]\s*=\s*(?:array\s*\(|\[)(.*?)(?:\)|\])\s*;`)
var commentLine = regexp.MustCompile(`(?m)^\s*(\*|/\*|//|#).*$`)

func drupalWeb(root string) string {
	for _, w := range []string{"web", "docroot", "html", "public_html"} {
		if isFile(filepath.Join(root, w, "core/lib/Drupal.php")) {
			return w
		}
	}
	return ""
}

func init() {
	magentoCron := func(s *site) string {
		return "SELECT TIMESTAMPDIFF(MINUTE, MAX(finished_at), UTC_TIMESTAMP()) FROM " + s.Prefix + "cron_schedule WHERE status = 'success'"
	}
	magentoAddress := func(s *site) string {
		return webAddress(sqlValue(s, "SELECT value FROM "+s.Prefix+"core_config_data WHERE path = 'web/secure/base_url' AND scope = 'default' LIMIT 1"))
	}
	symfonyConsole := func(s *site) ([]string, string) { return []string{"php", "bin/console"}, "" }

	kinds = []*siteKindDef{
		{
			Name: "magento", Label: "Magento",
			At:      func(dir string) string { return here(readable(filepath.Join(dir, magentoMarker)), dir) },
			Version: magentoVersion,
			DB:      magentoDB,
			Console: noConsole("use the magento tool for bin/magento"),
			Address: magentoAddress, CronSQL: magentoCron,
			WebRoot: "pub", Uploads: []string{"pub/media/", "media/"},
			Skip: []string{"var/cache/", "var/page_cache/", "var/view_preprocessed/", "generated/code/", "generated/metadata/", "pub/static/_cache/", "dev/tests/", "dev/tools/"},
			Logs: []string{"var/log/exception.log", "var/log/system.log", "var/log/support_report.log"},
		},
		{
			// Magento 1 and OpenMage, its maintained continuation.
			Name: "openmage", Label: "OpenMage (Magento 1)",
			At: func(dir string) string {
				return here(readable(filepath.Join(dir, "app/etc/local.xml")) && isFile(filepath.Join(dir, "app/Mage.php")), dir)
			},
			Version: func(root string) string {
				t := fileText(filepath.Join(root, "app/Mage.php"))
				name := "OpenMage"
				i := strings.Index(t, "function getOpenMageVersionInfo")
				if i < 0 {
					name, i = "Magento", strings.Index(t, "function getVersionInfo")
				}
				if i < 0 {
					return ""
				}
				t = t[i:min(len(t), i+900)]
				var parts []string
				for _, k := range []string{"major", "minor", "revision", "patch"} {
					if v := firstMatch(t, `'`+k+`'\s*=>\s*'?(\d+)'?`); v != "" {
						parts = append(parts, v)
					}
				}
				if len(parts) == 0 {
					return ""
				}
				return name + " " + strings.Join(parts, ".")
			},
			DB: func(s *site) *dbConf {
				t := fileText(filepath.Join(s.Root, "app/etc/local.xml"))
				i := strings.Index(t, "<default_setup>")
				if i < 0 {
					return nil
				}
				block := t[i:]
				if e := strings.Index(block, "</default_setup>"); e > 0 {
					block = block[:e]
				}
				tag := func(text, name string) string {
					return strings.TrimSpace(firstMatch(text, `(?s)<`+name+`>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</`+name+`>`))
				}
				return hostConf(tag(block, "dbname"), tag(block, "username"), tag(block, "password"), tag(block, "host"), "", tag(t, "table_prefix"))
			},
			Console: noConsole("Magento 1 has no command line tool of its own; run its scripts in the shell folder (php shell/indexer.php) with run"),
			Address: magentoAddress, CronSQL: magentoCron,
			Uploads: []string{"media/"}, Skip: []string{"var/cache/", "var/session/", "var/full_page_cache/", "includes/src/"},
			Logs: []string{"var/log/exception.log", "var/log/system.log"},
		},
		{
			Name: "wordpress", Label: "WordPress",
			At: func(dir string) string {
				switch {
				case readable(filepath.Join(dir, "wp-config.php")):
					return dir
				// WordPress also accepts wp-config.php one folder above the install.
				case isFile(filepath.Join(dir, "wp-load.php")) && readable(filepath.Join(filepath.Dir(dir), "wp-config.php")) && !isFile(filepath.Join(filepath.Dir(dir), "wp-settings.php")):
					return dir
				}
				return ""
			},
			Version: wpVersion,
			DB:      func(s *site) *dbConf { return wpDB(s) },
			Console: noConsole("use the wp tool for wp-cli"),
			Address: func(s *site) string {
				if v := webAddress(sqlValue(s, "SELECT option_value FROM "+s.Prefix+"options WHERE option_name = 'home'")); v != "" {
					return v
				}
				return fromDomain(s)
			},
			Uploads: []string{"wp-content/uploads/"}, Logs: []string{"wp-content/debug.log"},
		},
		{
			Name: "prestashop", Label: "PrestaShop",
			At: func(dir string) string {
				if !isFile(filepath.Join(dir, "config/defines.inc.php")) {
					return ""
				}
				return here(readable(filepath.Join(dir, "app/config/parameters.php")) || readable(filepath.Join(dir, "config/settings.inc.php")), dir)
			},
			Version: func(root string) string {
				for _, f := range []string{"src/Core/Version.php", "app/AppKernel.php"} {
					if v := firstMatch(fileText(filepath.Join(root, f)), `const VERSION\s*=\s*'([^']+)'`); v != "" {
						return v
					}
				}
				return phpDefines(fileText(filepath.Join(root, "config/settings.inc.php")))["_PS_VERSION_"]
			},
			DB: func(s *site) *dbConf {
				if t := fileText(filepath.Join(s.Root, "app/config/parameters.php")); t != "" {
					p := phpPairs(t)
					return hostConf(p["database_name"], p["database_user"], p["database_password"], p["database_host"], p["database_port"], p["database_prefix"])
				}
				d := phpDefines(fileText(filepath.Join(s.Root, "config/settings.inc.php"))) // 1.6
				return hostConf(d["_DB_NAME_"], d["_DB_USER_"], d["_DB_PASSWD_"], d["_DB_SERVER_"], "", d["_DB_PREFIX_"])
			},
			Console: func(s *site) ([]string, string) {
				if !isFile(filepath.Join(s.Root, "bin/console")) {
					return nil, "this PrestaShop (1.6) has no command line tool"
				}
				return []string{"php", "bin/console"}, ""
			},
			Address: func(s *site) string {
				if v := webAddress(sqlValue(s, "SELECT CONCAT('https://', domain_ssl, physical_uri) FROM "+s.Prefix+"shop_url WHERE main = 1 AND active = 1 LIMIT 1")); v != "" {
					return v
				}
				return fromDomain(s)
			},
			Uploads: []string{"img/", "upload/", "download/"}, Skip: []string{"var/cache/", "cache/"},
			Logs: []string{"var/logs/*.log", "log/*.log"},
		},
		{
			Name: "shopware", Label: "Shopware 6",
			At: func(dir string) string {
				return here(isFile(filepath.Join(dir, "bin/console")) && isDir(filepath.Join(dir, "vendor/shopware/core")), dir)
			},
			Version: func(root string) string {
				for _, f := range []string{"composer.lock", "vendor/composer/installed.json"} {
					if v := firstMatch(fileText(filepath.Join(root, f)), `"name":\s*"shopware/core",\s*"version":\s*"v?([^"]+)"`); v != "" {
						return v
					}
				}
				return ""
			},
			DB: func(s *site) *dbConf {
				return dbFromURL(dotenv(s.env, filepath.Join(s.Root, ".env"), filepath.Join(s.Root, ".env.local"))["DATABASE_URL"])
			},
			Console: symfonyConsole,
			Address: func(s *site) string {
				if v := webAddress(sqlValue(s, "SELECT url FROM sales_channel_domain WHERE url LIKE 'http%' ORDER BY created_at LIMIT 1")); v != "" {
					return v
				}
				return webAddress(dotenv(s.env, filepath.Join(s.Root, ".env"), filepath.Join(s.Root, ".env.local"))["APP_URL"])
			},
			CronSQL: func(s *site) string {
				return "SELECT TIMESTAMPDIFF(MINUTE, MAX(last_execution_time), UTC_TIMESTAMP()) FROM scheduled_task"
			},
			WebRoot: "public", Uploads: []string{"public/media/", "public/thumbnail/"}, Skip: []string{"var/cache/", "public/theme/", "public/bundles/"},
			Logs: []string{"var/log/*.log"},
		},
		{
			Name: "drupal", Label: "Drupal",
			At: func(dir string) string {
				if drupalWeb(dir) != "" {
					return dir
				}
				if !isFile(filepath.Join(dir, "core/lib/Drupal.php")) {
					return ""
				}
				// The folder served is inside a composer project: the project is the site.
				if p := filepath.Dir(dir); drupalWeb(p) == filepath.Base(dir) && isFile(filepath.Join(p, "composer.json")) {
					return p
				}
				return dir
			},
			Version: func(root string) string {
				return firstMatch(fileText(filepath.Join(root, drupalWeb(root), "core/lib/Drupal.php")), `const VERSION\s*=\s*'([^']+)'`)
			},
			DB: func(s *site) *dbConf {
				t := commentLine.ReplaceAllString(fileText(filepath.Join(s.Root, drupalWeb(s.Root), "sites/default/settings.php")), "")
				var p map[string]string
				for _, m := range drupalDB.FindAllStringSubmatch(t, -1) {
					p = phpPairs(m[1]) // the last assignment wins, as in PHP
				}
				if p == nil || !mysqlKind(p["driver"]) {
					return nil
				}
				return hostConf(p["database"], p["username"], p["password"], p["host"], p["port"], p["prefix"])
			},
			Console: func(s *site) ([]string, string) {
				if !isFile(filepath.Join(s.Root, "vendor/bin/drush")) {
					return nil, "drush is not installed in this project; add it with: composer require drush/drush"
				}
				return []string{"vendor/bin/drush"}, ""
			},
			Address: fromDomain,
		},
		{
			Name: "joomla", Label: "Joomla",
			At: func(dir string) string {
				return here(readable(filepath.Join(dir, "configuration.php")) && (isFile(filepath.Join(dir, "libraries/src/Version.php")) || isFile(filepath.Join(dir, "libraries/cms/version/version.php"))), dir)
			},
			Version: func(root string) string {
				t := fileText(filepath.Join(root, "libraries/src/Version.php"))
				var parts []string
				for _, k := range []string{"MAJOR_VERSION", "MINOR_VERSION", "PATCH_VERSION"} {
					if v := firstMatch(t, `const `+k+`\s*=\s*(\d+)`); v != "" {
						parts = append(parts, v)
					}
				}
				if len(parts) == 0 {
					return firstMatch(fileText(filepath.Join(root, "libraries/cms/version/version.php")), `RELEASE\s*=\s*'([^']+)'`)
				}
				return strings.Join(parts, ".")
			},
			DB: func(s *site) *dbConf {
				p := map[string]string{}
				for _, m := range regexp.MustCompile(`public\s+\$(\w+)\s*=\s*`+phpString+`\s*;`).FindAllStringSubmatch(fileText(filepath.Join(s.Root, "configuration.php")), -1) {
					p[m[1]] = phpUnquote(m[2], m[3])
				}
				if !mysqlKind(p["dbtype"]) {
					return nil
				}
				return hostConf(p["db"], p["user"], p["password"], p["host"], "", p["dbprefix"])
			},
			Console: func(s *site) ([]string, string) {
				if !isFile(filepath.Join(s.Root, "cli/joomla.php")) {
					return nil, "this Joomla (before 4) has no command line tool"
				}
				return []string{"php", "cli/joomla.php"}, ""
			},
			Address: fromDomain,
			Uploads: []string{"images/"}, Skip: []string{"cache/", "administrator/cache/", "tmp/"},
			Logs: []string{"administrator/logs/*.php", "logs/*.php"},
		},
		{
			Name: "opencart", Label: "OpenCart",
			At: func(dir string) string {
				return here(readable(filepath.Join(dir, "config.php")) && isFile(filepath.Join(dir, "system/startup.php")) && isDir(filepath.Join(dir, "catalog")), dir)
			},
			Version: func(root string) string { return phpDefines(fileText(filepath.Join(root, "index.php")))["VERSION"] },
			DB: func(s *site) *dbConf {
				d := phpDefines(fileText(filepath.Join(s.Root, "config.php")))
				if !mysqlKind(d["DB_DRIVER"]) {
					return nil
				}
				return hostConf(d["DB_DATABASE"], d["DB_USERNAME"], d["DB_PASSWORD"], d["DB_HOSTNAME"], d["DB_PORT"], d["DB_PREFIX"])
			},
			Console: noConsole("OpenCart has no command line tool"),
			Address: func(s *site) string {
				d := phpDefines(fileText(filepath.Join(s.Root, "config.php")))
				for _, k := range []string{"HTTPS_SERVER", "HTTP_SERVER"} {
					if v := webAddress(d[k]); v != "" {
						return v
					}
				}
				return fromDomain(s)
			},
			Uploads: []string{"image/"}, Skip: []string{"system/storage/cache/", "system/storage/modification/"},
			Logs: []string{"system/storage/logs/*.log"},
		},
		{
			// Last: any Laravel application, whatever it is used for.
			Name: "laravel", Label: "Laravel",
			At: func(dir string) string {
				return here(isFile(filepath.Join(dir, "artisan")) && isDir(filepath.Join(dir, "vendor/laravel/framework")), dir)
			},
			Version: func(root string) string {
				return firstMatch(fileText(filepath.Join(root, "vendor/laravel/framework/src/Illuminate/Foundation/Application.php")), `const VERSION\s*=\s*'([^']+)'`)
			},
			DB: func(s *site) *dbConf {
				e := dotenv(s.env, filepath.Join(s.Root, ".env"))
				if u := e["DB_URL"]; u != "" {
					return dbFromURL(u)
				}
				if !mysqlKind(e["DB_CONNECTION"]) {
					return nil
				}
				return hostConf(e["DB_DATABASE"], e["DB_USERNAME"], e["DB_PASSWORD"], e["DB_HOST"], e["DB_PORT"], "")
			},
			Console: func(s *site) ([]string, string) { return []string{"php", "artisan"}, "" },
			// APP_URL is often left at whatever it was on the developer's machine or an
			// old domain: the name the web server answers to is the better witness.
			Address: func(s *site) string {
				if v := fromDomain(s); v != "" {
					return v
				}
				return webAddress(dotenv(s.env, filepath.Join(s.Root, ".env"))["APP_URL"])
			},
			WebRoot: "public", Uploads: []string{"storage/app/public/", "public/uploads/"}, Skip: []string{"storage/framework/", "bootstrap/cache/"},
			Logs: []string{"storage/logs/*.log"},
		},
		{
			// Ghost as ghost-cli installs it (config.production.json, current -> versions/<v>, content/),
			// or the official Docker image (the same layout under /var/lib/ghost, settings in variables).
			Name: "ghost", Label: "Ghost",
			At: func(dir string) string {
				return here((isFile(filepath.Join(dir, "config.production.json")) || isFile(filepath.Join(dir, "config.development.json")) || isFile(filepath.Join(dir, ".ghost-cli"))) && isFile(filepath.Join(dir, "current/package.json")), dir)
			},
			Version: func(root string) string {
				return firstMatch(fileText(filepath.Join(root, "current/package.json")), `"version":\s*"([^"]+)"`)
			},
			DB: func(s *site) *dbConf {
				c := ghostConfig(s)
				if !mysqlKind(c["database__client"]) {
					return nil
				}
				return hostConf(c["database__connection__database"], c["database__connection__user"], c["database__connection__password"], c["database__connection__host"], c["database__connection__port"], "")
			},
			// ghost-cli, run in the install folder as its owner (it refuses root).
			Console: func(s *site) ([]string, string) {
				if _, err := exec.LookPath("ghost"); err != nil {
					return nil, "ghost-cli is not installed (npm install -g ghost-cli@latest)"
				}
				return []string{"ghost"}, ""
			},
			Address: func(s *site) string {
				if v := webAddress(ghostConfig(s)["url"]); v != "" {
					return v
				}
				return fromDomain(s)
			},
			Uploads: []string{"content/images/", "content/media/", "content/files/"}, Skip: []string{"versions/", "current/", "content/logs/"},
			Logs: []string{"content/logs/*.log"},
		},
	}
}

// Ghost's settings, flattened the way Ghost itself reads them from variables
// (database__connection__host): the JSON file first, the container's variables on top.
func ghostConfig(s *site) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"config.development.json", "config.production.json"} {
		var doc map[string]any
		if json.Unmarshal([]byte(fileText(filepath.Join(s.Root, name))), &doc) == nil {
			flattenInto(out, "", doc)
		}
	}
	for k, v := range s.env {
		if strings.Contains(k, "__") || k == "url" {
			out[k] = v
		}
	}
	return out
}

func flattenInto(out map[string]string, prefix string, v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			flattenInto(out, prefix+k+"__", child)
		}
	case string:
		out[strings.TrimSuffix(prefix, "__")] = x
	case float64:
		out[strings.TrimSuffix(prefix, "__")] = strings.TrimSuffix(strings.TrimSuffix(strconv.FormatFloat(x, 'f', 2, 64), "00"), ".")
	case bool:
		out[strings.TrimSuffix(prefix, "__")] = strconv.FormatBool(x)
	}
}

// consoleName is how list_sites names a site's command line tool.
func consoleName(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return strings.TrimPrefix(strings.Join(argv, " "), "php ")
}

// kindLogs: a site's own log files, newest first when a glob matches several.
func kindLogs(s *site) []string {
	k := kindOf(s.Kind)
	if k == nil {
		return nil
	}
	var out []string
	for _, g := range k.Logs {
		m, _ := filepath.Glob(filepath.Join(s.Root, g))
		sort.Slice(m, func(i, j int) bool {
			a, _ := os.Stat(m[i])
			b, _ := os.Stat(m[j])
			return a != nil && b != nil && a.ModTime().After(b.ModTime())
		})
		if len(m) > 4 {
			m = m[:4]
		}
		out = append(out, m...)
	}
	return out
}
