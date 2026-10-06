package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mk(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// describe a folder as the agent would, without the web server's configuration.
func known(t *testing.T, dir string) *site {
	t.Helper()
	k, root := siteAt(dir)
	if k == nil {
		t.Fatalf("no site recognised at %s", dir)
	}
	return describeSite(&site{Kind: k.Name, Root: root}, nil)
}

func wantDB(t *testing.T, s *site, name, user, password, host, port, prefix string) {
	t.Helper()
	if s.db == nil {
		t.Fatalf("%s: database settings not read (%s)", s.Kind, s.Note)
	}
	if got := []string{s.db.Name, s.db.User, s.db.Password, s.db.Host, s.db.Port, s.db.Prefix}; strings.Join(got, "|") != strings.Join([]string{name, user, password, host, port, prefix}, "|") {
		t.Fatalf("%s database: got %q", s.Kind, got)
	}
}

func TestKinds(t *testing.T) {
	d := t.TempDir()

	mk(t, d+"/presta", map[string]string{
		"config/defines.inc.php": "<?php",
		"bin/console":            "#!/usr/bin/env php",
		"app/AppKernel.php":      "<?php class AppKernel { const VERSION = '8.1.7'; const MAJOR_VERSION = 8; }",
		"app/config/parameters.php": `<?php return array (
  'parameters' =>
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'presta',
    'database_user' => 'ps_user',
    'database_password' => 'it\'s "quoted" \\ here',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_password' => NULL,
    'secret' => 'abc',
  ),
);`,
	})
	s := known(t, d+"/presta")
	if s.Kind != "prestashop" || s.Version != "8.1.7" || s.Console != "bin/console" {
		t.Fatalf("prestashop: %+v", s)
	}
	wantDB(t, s, "presta", "ps_user", `it's "quoted" \ here`, "127.0.0.1", "", "ps_")

	mk(t, d+"/presta16", map[string]string{
		"config/defines.inc.php":  "<?php",
		"config/settings.inc.php": "<?php\ndefine('_DB_SERVER_', 'localhost:3307');\ndefine('_DB_NAME_', 'old');\ndefine('_DB_USER_', 'u');\ndefine('_DB_PASSWD_', 'p');\ndefine('_DB_PREFIX_', 'ps_');\ndefine('_PS_VERSION_', '1.6.1.24');",
	})
	s = known(t, d+"/presta16")
	if s.Kind != "prestashop" || s.Version != "1.6.1.24" || s.Console != "" {
		t.Fatalf("prestashop 1.6: %+v", s)
	}
	wantDB(t, s, "old", "u", "p", "localhost", "3307", "ps_")

	mk(t, d+"/shopware", map[string]string{
		"bin/console":                        "#!/usr/bin/env php",
		"vendor/shopware/core/composer.json": "{}",
		"composer.lock":                      `{"packages": [{"name": "shopware/administration", "version": "v6.6.4.1"}, {"name": "shopware/core", "version": "v6.6.4.1", "source": {}}]}`,
		".env":                               "APP_ENV=prod\nAPP_URL=http://127.0.0.1:8000\nDATABASE_URL=mysql://root:root@localhost/shopware\n",
		".env.local":                         "# set by the installer\nAPP_URL=\"https://shop.example\"\nDATABASE_URL=\"mysql://sw:p%40ss%2Fword@db.internal:3307/sw6\"\n",
	})
	s = known(t, d+"/shopware")
	if s.Kind != "shopware" || s.Version != "6.6.4.1" || s.Console != "bin/console" || s.WebRoot != "public" {
		t.Fatalf("shopware: %+v", s)
	}
	wantDB(t, s, "sw6", "sw", "p@ss/word", "db.internal", "3307", "")

	mk(t, d+"/drupal", map[string]string{
		"composer.json":           "{}",
		"vendor/bin/drush":        "#!/usr/bin/env php",
		"web/core/lib/Drupal.php": "<?php class Drupal { const VERSION = '10.3.6'; }",
		"web/sites/default/settings.php": `<?php
/**
 * @code
 * $databases['default']['default'] = [
 *   'database' => 'databasename',
 *   'username' => 'sqlusername',
 * ];
 * @endcode
 */
# $databases['default']['default'] = ['database' => 'commented'];
$databases = [];
$settings['hash_salt'] = 'x';
$databases['default']['default'] = array (
  'database' => 'drupal10',
  'username' => 'dru',
  'password' => 'se)cret',
  'prefix' => '',
  'host' => 'localhost',
  'port' => '3306',
  'driver' => 'mysql',
  'namespace' => 'Drupal\\mysql\\Driver\\Database\\mysql',
);`,
	})
	for _, at := range []string{d + "/drupal", d + "/drupal/web"} { // the project or the folder served: one site
		s = known(t, at)
		if s.Kind != "drupal" || s.Root != d+"/drupal" || s.Version != "10.3.6" || s.WebRoot != "web" || s.Console != "vendor/bin/drush" {
			t.Fatalf("drupal at %s: %+v", at, s)
		}
		wantDB(t, s, "drupal10", "dru", "se)cret", "localhost", "3306", "")
	}
	mk(t, d+"/drupal-pg", map[string]string{
		"core/lib/Drupal.php":        "<?php const VERSION = '11.0.1';",
		"sites/default/settings.php": "<?php $databases['default']['default'] = ['database' => 'x', 'driver' => 'pgsql'];",
	})
	if s = known(t, d+"/drupal-pg"); s.db != nil || s.Note == "" || s.Root != d+"/drupal-pg" {
		t.Fatalf("drupal on PostgreSQL should have no database settings and a note: %+v", s)
	}

	mk(t, d+"/joomla", map[string]string{
		"cli/joomla.php":            "<?php",
		"libraries/src/Version.php": "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 2; public const PATCH_VERSION = 1; }",
		"configuration.php":         "<?php\nclass JConfig {\n\tpublic $dbtype = 'mysqli';\n\tpublic $host = 'localhost';\n\tpublic $user = 'joom';\n\tpublic $password = 'p\\'w';\n\tpublic $db = 'joomla5';\n\tpublic $dbprefix = 'j5_';\n\tpublic $live_site = '';\n}",
	})
	s = known(t, d+"/joomla")
	if s.Kind != "joomla" || s.Version != "5.2.1" || s.Console != "cli/joomla.php" {
		t.Fatalf("joomla: %+v", s)
	}
	wantDB(t, s, "joomla5", "joom", "p'w", "localhost", "", "j5_")

	mk(t, d+"/opencart", map[string]string{
		"index.php":          "<?php\n// Version\ndefine('VERSION', '4.0.2.3');",
		"system/startup.php": "<?php",
		"catalog/index.html": "",
		"config.php":         "<?php\ndefine('HTTP_SERVER', 'https://cart.example/');\ndefine('DB_DRIVER', 'mysqli');\ndefine('DB_HOSTNAME', 'localhost');\ndefine('DB_USERNAME', 'oc');\ndefine('DB_PASSWORD', 'pw');\ndefine('DB_DATABASE', 'opencart');\ndefine('DB_PORT', '3306');\ndefine('DB_PREFIX', 'oc_');",
	})
	s = known(t, d+"/opencart")
	if s.Kind != "opencart" || s.Version != "4.0.2.3" || kindOf("opencart").Address(s) != "https://cart.example/" {
		t.Fatalf("opencart: %+v", s)
	}
	wantDB(t, s, "opencart", "oc", "pw", "localhost", "3306", "oc_")

	mk(t, d+"/laravel", map[string]string{
		"artisan": "#!/usr/bin/env php",
		"vendor/laravel/framework/src/Illuminate/Foundation/Application.php": "<?php class Application { const VERSION = '11.26.0'; }",
		".env": "APP_NAME=\"My App\"\nAPP_URL=https://app.example\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=app\nDB_USERNAME=app_user # the app's own\nDB_PASSWORD=\"p#ss word\"\n",
	})
	s = known(t, d+"/laravel")
	if s.Kind != "laravel" || s.Version != "11.26.0" || s.Console != "artisan" || s.WebRoot != "public" || kindOf("laravel").Address(s) != "https://app.example" {
		t.Fatalf("laravel: %+v", s)
	}
	// The name the web server answers to wins over APP_URL, which is often stale.
	s.Domains = []string{"real.example"}
	if got := kindOf("laravel").Address(s); got != "https://real.example/" {
		t.Fatalf("laravel address: %s", got)
	}
	wantDB(t, s, "app", "app_user", "p#ss word", "127.0.0.1", "3306", "")

	mk(t, d+"/ghost", map[string]string{
		"config.production.json": `{"url": "https://blog.example", "server": {"port": 2368}, "database": {"client": "mysql", "connection": {"host": "127.0.0.1", "port": 3306, "user": "ghost", "password": "gh#pw", "database": "ghost_prod"}}}`,
		"current/package.json":   `{"name": "ghost", "version": "5.105.0"}`,
		"content/images/.keep":   "",
	})
	s = known(t, d+"/ghost")
	if s.Kind != "ghost" || s.Version != "5.105.0" || kindOf("ghost").Address(s) != "https://blog.example" {
		t.Fatalf("ghost: %+v", s)
	}
	wantDB(t, s, "ghost_prod", "ghost", "gh#pw", "127.0.0.1", "3306", "")
	// The Docker image: settings in variables, which win over the file.
	s.env = map[string]string{"database__client": "mysql", "database__connection__host": "db", "database__connection__user": "root", "database__connection__password": "x", "database__connection__database": "ghost", "url": "https://docker.example"}
	s.db = kindOf("ghost").DB(s)
	wantDB(t, s, "ghost", "root", "x", "db", "3306", "") // the port stays from the file: variables only replace what they name
	if got := kindOf("ghost").Address(s); got != "https://docker.example" {
		t.Fatalf("ghost address from variables: %s", got)
	}
	s.env = nil
	// SQLite: no database settings, and not a failure.
	mk(t, d+"/ghost-lite", map[string]string{
		"config.production.json": `{"url": "https://lite.example", "database": {"client": "sqlite3", "connection": {"filename": "content/data/ghost.db"}}}`,
		"current/package.json":   `{"name": "ghost", "version": "5.0.0"}`,
	})
	if s = known(t, d+"/ghost-lite"); s.Kind != "ghost" || kindOf("ghost").DB(s) != nil {
		t.Fatalf("ghost sqlite: %+v", s)
	}

	mk(t, d+"/m1", map[string]string{
		"app/Mage.php": "<?php final class Mage {\n public static function getVersionInfo() { return array('major' => '1', 'minor' => '9', 'revision' => '4', 'patch' => '5', 'stability' => ''); }\n public static function getOpenMageVersionInfo() { return ['major' => '20', 'minor' => '10', 'patch' => '2']; }\n}",
		"app/etc/local.xml": `<config><global><resources>
 <db><table_prefix><![CDATA[mg_]]></table_prefix></db>
 <default_setup><connection>
  <host><![CDATA[localhost]]></host><username><![CDATA[m1]]></username><password><![CDATA[p<w>]]></password><dbname><![CDATA[magento1]]></dbname>
  <active>1</active>
 </connection></default_setup>
</resources></global></config>`,
	})
	s = known(t, d+"/m1")
	if s.Kind != "openmage" || s.Version != "OpenMage 20.10.2" {
		t.Fatalf("openmage: %+v", s)
	}
	wantDB(t, s, "magento1", "m1", "p<w>", "localhost", "", "mg_")

	// A WordPress that is a shop says so.
	mk(t, d+"/woo", map[string]string{
		"wp-config.php": "<?php define('DB_NAME', 'woo'); define('DB_USER', 'w'); define('DB_PASSWORD', 'x'); $table_prefix = 'wp_';",
		"wp-load.php":   "<?php",
		"wp-content/plugins/woocommerce/woocommerce.php": "<?php\n/**\n * Plugin Name: WooCommerce\n * Version: 9.3.3\n * Requires PHP: 7.4\n */",
	})
	if s = known(t, d+"/woo"); s.Kind != "wordpress" || s.Woo != "9.3.3" {
		t.Fatalf("woocommerce: %+v", s)
	}

	// Folders that are none of these.
	mk(t, d+"/plain", map[string]string{"index.php": "<?php", "config.php": "<?php", "artisan": "x"})
	if k, _ := siteAt(d + "/plain"); k != nil {
		t.Fatalf("a plain folder was taken for %s", k.Name)
	}
}

func TestWebAddress(t *testing.T) {
	for in, keep := range map[string]bool{
		"https://shop.example/": true, "http://shop.example": true, "http://127.0.0.1:8080": false, "http://localhost/": false,
		"https://10.0.0.5/": false, "http://192.168.1.10": false, "http://[::1]/": false, "shop.example": false, "": false, "http://app.internal": false,
	} {
		if got := webAddress(in) != ""; got != keep {
			t.Errorf("%q: kept %v, want %v", in, got, keep)
		}
	}
}

func TestDotenv(t *testing.T) {
	d := t.TempDir()
	mk(t, d, map[string]string{".env": "A=1\nexport B='two words'\nC=\"x ${A}\"\n#D=no\nE=plain # note\n", ".env.local": "A=2\n"})
	e := dotenv(map[string]string{"E": "from the container"}, d+"/.env", d+"/.env.local", d+"/.env.missing")
	if e["A"] != "2" || e["B"] != "two words" || e["C"] != "x 2" || e["D"] != "" || e["E"] != "from the container" {
		t.Fatalf("%v", e)
	}
}

const inspectSample = `[
 {"Id":"aaa","Name":"/shop-wordpress-1","Config":{"Env":["WORDPRESS_DB_HOST=db:3306","WORDPRESS_DB_USER=wp","WORDPRESS_DB_PASSWORD=pw=1","WORDPRESS_DB_NAME=shop","VIRTUAL_HOST=shop.example,www.shop.example"],
   "Labels":{"com.docker.compose.service":"wordpress","traefik.http.routers.shop.rule":"Host(` + "`blog.example`" + `) || Host(` + "`b.example`, `c.example`" + `) && PathPrefix(` + "`/x`" + `)","caddy_0":"https://caddy.example"}},
  "Mounts":[{"Type":"volume","Source":"MOUNT","Destination":"/var/www/html"},{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"}],
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.20.0.3","Aliases":["wordpress"],"DNSNames":["shop-wordpress-1","wordpress"]}}}},
 {"Id":"bbb","Name":"/shop-db-1","Config":{"Env":["MARIADB_DATABASE=shop"],"Labels":{"com.docker.compose.service":"db"}},
  "Mounts":[{"Type":"volume","Source":"/var/lib/docker/volumes/shop_db/_data","Destination":"/var/lib/mysql"}],
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.20.0.2","Aliases":["db"]}}}},
 {"Id":"ccc","Name":"/other-db-1","Config":{"Labels":{"com.docker.compose.service":"db"}},"Mounts":[],
  "NetworkSettings":{"Networks":{"other_default":{"IPAddress":"172.21.0.2","Aliases":["db"]}}}}
]`

func TestDockerSites(t *testing.T) {
	d := t.TempDir()
	mk(t, d+"/vol", map[string]string{
		"wp-load.php":   "<?php",
		"wp-config.php": "<?php define( 'DB_NAME', getenv_docker('WORDPRESS_DB_NAME', 'wordpress') );\n$table_prefix = getenv_docker('WORDPRESS_TABLE_PREFIX', 'wp_');",
	})
	boxes := parseDockerInspect([]byte(strings.ReplaceAll(inspectSample, "MOUNT", d+"/vol")))
	if len(boxes) != 3 || boxes[0].Name != "shop-wordpress-1" || len(boxes[0].Mounts) != 2 || boxes[0].Env["WORDPRESS_DB_PASSWORD"] != "pw=1" {
		t.Fatalf("inspect: %+v", boxes[0])
	}
	// The database host is a name only containers know: the one on the same network answers to it.
	if ip := boxes[0].reach("db", boxes); ip != "172.20.0.2" {
		t.Fatalf("db resolved to %s", ip)
	}
	if ip := boxes[0].reach("nobody", boxes); ip != "nobody" {
		t.Fatalf("an unknown name should stay as it is: %s", ip)
	}
	if got := strings.Join(boxes[0].domains(), " "); !strings.Contains(got, "blog.example") || !strings.Contains(got, "c.example") || !strings.Contains(got, "caddy.example") || !strings.Contains(got, "www.shop.example") || strings.Contains(got, "/x") {
		t.Fatalf("domains: %s", got)
	}
	dockerCache.at, dockerCache.boxes = time.Now(), boxes
	defer func() { dockerCache.boxes = nil }()
	var found *site
	for _, f := range dockerFolders() {
		if k, root := siteAt(f.dir); k != nil {
			found = describeSite(&site{Kind: k.Name, Root: root, box: f.in.box, Container: f.in.box.Name, InPath: f.in.inside(root)}, nil)
		}
	}
	if found == nil || found.Container != "shop-wordpress-1" || found.InPath != "/var/www/html" {
		t.Fatalf("site in a container: %+v", found)
	}
	wantDB(t, found, "shop", "wp", "pw=1", "172.20.0.2", "3306", "wp_")
	argv := found.inBox([]string{"wp", "plugin", "list"})
	if got := strings.Join(argv, " "); !strings.HasPrefix(got, "docker exec -w /var/www/html -u ") || !strings.HasSuffix(got, " shop-wordpress-1 wp plugin list") {
		t.Fatalf("command in the container: %s", got)
	}
	if m := (&boxMount{boxes[0], boxes[0].Mounts[0]}); m.inside(d+"/vol/sub/dir") != "/var/www/html/sub/dir" {
		t.Fatalf("path in the container: %s", m.inside(d+"/vol/sub/dir"))
	}
}
