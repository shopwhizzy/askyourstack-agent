package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Rules in the shape of the hub's scan_rules.json, one of each kind. The
// signatures here are made up for the test: none is a real malware pattern.
const testRules = `[
 {"id":"t-pattern","title":"marker in code","category":"malware","severity":"critical","scope":"app pub","extensions":["php","phtml"],"pattern":"zz_marker[[:space:]]*\\(","exclude_pattern":"Allowed/|.{300,}"},
 {"id":"t-anyfile","title":"dropper line","category":"malware","severity":"critical","scope":"pub/media","extensions":[],"pattern":"fetchit[[:space:]]+http.*-o[[:space:]]+.*\\.php","exclude_dirs":["cache"]},
 {"id":"t-bracket","title":"hash gate","category":"malware","severity":"critical","scope":"app","extensions":["php"],"pattern":"md5[[:space:]]*\\(\\$_COOKIE\\[[^]]*\\]\\)[[:space:]]*(===?|!==?)"},
 {"id":"t-absent","title":"patch missing","category":"vulnerability","severity":"critical","check_type":"signature_absent","scope":"vendor/x/Processor.php","fix_pattern":"isTypeSimple\\(\\$parameterType\\)"},
 {"id":"t-absent-ok","title":"patch missing","category":"vulnerability","severity":"critical","check_type":"signature_absent","scope":"vendor/x/Patched.php","fix_pattern":"isTypeSimple\\("},
 {"id":"t-composer","title":"old module","category":"vulnerability","severity":"warning","check_type":"composer_package_version","composer_name":"acme/module-geoip","vulnerable_below":"1.7.4"},
 {"id":"t-composer-ok","title":"old module","category":"vulnerability","severity":"warning","check_type":"composer_package_version","composer_name":"acme/module-new","vulnerable_below":"1.9.10"},
 {"id":"t-path","title":"leftover archive","category":"suspicious","severity":"warning","check_type":"path_exists","scope":".","filename_patterns":["*.sql","*.zip"],"exclude_pattern":"vendor/|pub/media/downloadable/","path_exists_message":"Defunct file detected"},
 {"id":"t-host","title":"host check","category":"malware","severity":"critical","check_type":"host_command","command":"echo \"HOSTHIT|t-host|process:1/x|runs from ${USERACCT:-anyone}\"; echo noise","remediation":"Kill it."},
 {"id":"t-host-root","title":"root only","category":"malware","severity":"critical","check_type":"host_command","master_only":true,"command":"echo 'HOSTHIT|t-host-root|/etc/x|seen'"},
 {"id":"t-badregex","title":"broken","severity":"critical","scope":"app","pattern":"(unclosed"},
 {"id":"t-unknown","title":"new kind","severity":"critical","check_type":"something_new"},
 {"id":"t-wp-only","title":"wordpress thing","severity":"critical","kinds":["wordpress"],"check_type":"path_exists","scope":".","filename_patterns":["backup.sql"]},
 {"id":"t-gitdir","title":"repository in the web folder","severity":"warning","kinds":["magento"],"check_type":"path_exists","scope":"pub","filename_patterns":[".git",".env"]},
 {"id":"t-siteroot","title":"uses the site folder","severity":"warning","check_type":"host_command","command":"echo \"HOSTHIT|t-siteroot|$SITEROOT/app|ok\""},
 {"id":"t-report","title":"marker in a report","severity":"critical","scope":"var/report","pattern":"x_trace_"},
 {"id":"t-dbonly","title":"order field","category":"suspicious","severity":"warning","scope":"","filesystem_scan":false,"scan_db":true,"extensions":[],"pattern":"this\\.getTemplateFilter\\(\\)"}
]`

func TestRuleScan(t *testing.T) {
	d := t.TempDir()
	put(t, d+"/app/code/A/a.php", "<?php\n// fine\nzz_marker ($x);\n")
	put(t, d+"/app/code/Allowed/b.php", "<?php zz_marker($x);\n")
	put(t, d+"/app/code/A/long.phtml", "<?php "+strings.Repeat("x", 400)+" zz_marker(1);\n")
	put(t, d+"/app/code/A/c.js", "zz_marker(1)\n")
	put(t, d+"/lib/d.php", "<?php zz_marker(1);\n") // outside the rule's folders
	put(t, d+"/app/gate.php", "<?php if (md5($_COOKIE['k']) === 'abc') { run(); }\n")
	put(t, d+"/pub/media/customer/sess_1", "x\nfetchit http://x.example/a -o /var/www/s.php\n")
	put(t, d+"/pub/media/catalog/cache/sess_2", "fetchit http://x.example/a -o s.php\n")
	put(t, d+"/vendor/x/Processor.php", "<?php // unpatched\n")
	put(t, d+"/vendor/x/Patched.php", "<?php if ($this->isTypeSimple($parameterType)) {}\n")
	put(t, d+"/composer.lock", `{"packages":[{"name":"acme/module-geoip","version":"v1.7.3"},{"name":"acme/module-new","version":"1.9.10"}]}`)
	put(t, d+"/backup.sql", "x")
	put(t, d+"/vendor/pkg/fixture.zip", "x")
	put(t, d+"/pub/media/downloadable/file.zip", "x")
	put(t, d+"/var/export/old.sql", "x")           // var is not walked,
	put(t, d+"/var/report/12/345", "a x_trace_ b") // except the part a rule names
	put(t, d+"/var/cache/report", "x_trace_")
	put(t, d+"/pub/.git/HEAD", "ref: refs/heads/main")
	put(t, d+"/.git/HEAD", "ref: refs/heads/main") // outside pub: not served

	rules, skipped := parseRules([]byte(testRules))
	if strings.Join(skipped, ",") != "t-badregex,t-unknown" {
		t.Errorf("skipped %v", skipped)
	}
	var found []finding
	rep := ruleScan(&site{Kind: "magento", Root: d, Owner: "shopuser"}, rules, func(f finding) { found = append(found, f) })
	got := map[string][]finding{}
	for _, f := range found {
		id := f.What[strings.LastIndex(f.What, "[")+1 : len(f.What)-1]
		got[id] = append(got[id], f)
	}
	one := func(id, where, detail string) {
		t.Helper()
		if len(got[id]) != 1 || got[id][0].Where != where || !strings.Contains(got[id][0].Detail, detail) {
			t.Errorf("%s: got %+v, want one at %s holding %q", id, got[id], where, detail)
		}
	}
	one("t-pattern", "app/code/A/a.php:3", "zz_marker ($x);")
	one("t-anyfile", "pub/media/customer/sess_1:2", "fetchit")
	one("t-bracket", "app/gate.php:1", "md5(")
	one("t-absent", "vendor/x/Processor.php", "fix is not in this file")
	one("t-composer", "composer.lock", "acme/module-geoip v1.7.3 is installed; fixed in 1.7.4")
	one("t-path", "backup.sql", "Defunct file detected")
	if len(got["t-absent-ok"])+len(got["t-composer-ok"])+len(got["t-dbonly"]) != 0 {
		t.Errorf("clean checks reported: %+v %+v %+v", got["t-absent-ok"], got["t-composer-ok"], got["t-dbonly"])
	}
	one("t-report", "var/report/12/345:1", "x_trace_")
	one("t-gitdir", "pub/.git", "should not be inside")
	one("t-siteroot", d+"/app", "ok")
	if len(got["t-wp-only"]) != 0 {
		t.Errorf("a WordPress rule ran on a Magento site: %+v", got["t-wp-only"])
	}
	one("t-host", "process:1/x", "runs from shopuser\nWhat to do: Kill it.")
	if got["t-pattern"][0].Severity != "high" || got["t-composer"][0].Severity != "medium" || !strings.HasPrefix(got["t-pattern"][0].What, "malware: marker in code") {
		t.Errorf("severity or title: %+v %+v", got["t-pattern"][0], got["t-composer"][0])
	}
	if privileged {
		one("t-host-root", "/etc/x", "seen")
	} else if len(got["t-host-root"]) != 0 || len(rep.Skipped) != 1 {
		t.Errorf("root-only rule ran without root: %+v %v", got["t-host-root"], rep.Skipped)
	}
	if rep.Rules != len(rules)-1 || rep.Files < 5 { // all but the WordPress-only rule
		t.Errorf("report %+v", rep)
	}
}

func TestRulesTravelScrambled(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "rules")
	f.Write(scramble([]byte(testRules)))
	f.Close()
	if b, _ := os.ReadFile(f.Name()); strings.Contains(string(b), "zz_marker") {
		t.Error("the rules file holds a readable signature")
	}
	rules, _ := loadRules(f.Name())
	if len(rules) != 15 {
		t.Errorf("loaded %d rules", len(rules))
	}
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("the rules file was left behind")
	}
}

func TestManyHitsAreCounted(t *testing.T) {
	d := t.TempDir()
	for i := 0; i < 12; i++ {
		put(t, d+"/app/f"+string(rune('a'+i))+".php", "<?php zz_marker(1);\n")
	}
	rules, _ := parseRules([]byte(`[{"id":"t","title":"x","severity":"critical","scope":"app","extensions":["php"],"pattern":"zz_marker"}]`))
	var found []finding
	ruleScan(&site{Kind: "magento", Root: d}, rules, func(f finding) { found = append(found, f) })
	if len(found) != ruleHitsMax+1 || !strings.Contains(found[len(found)-1].What, "4 more matches") {
		b, _ := json.Marshal(found)
		t.Errorf("got %d findings: %s", len(found), b)
	}
}

func TestWordPressPackageRules(t *testing.T) {
	d := t.TempDir()
	put(t, d+"/wp-content/plugins/fast-cache/helper.php", "<?php // Version: 0.1 of a helper\n")
	put(t, d+"/wp-content/plugins/fast-cache/fast-cache.php", "<?php\n/**\n * Plugin Name: Fast Cache\n * Version:     6.3.0.1\n */\n")
	put(t, d+"/wp-content/plugins/safe-login/safe-login.php", "<?php\n/*\nPlugin Name: Safe Login\nVersion: 8.5.0\n*/\n")
	put(t, d+"/wp-content/themes/blocks/style.css", "/*\nTheme Name: Blocks\nVersion: 1.9.6\n*/\n")
	rules, skipped := parseRules([]byte(`[
	 {"id":"p-old","title":"Fast Cache below 6.4","severity":"critical","check_type":"wp_package_version","wp_plugin":"fast-cache","vulnerable_below":"6.4"},
	 {"id":"p-range","title":"Safe Login 9.0.0 to 9.1.1.1","severity":"critical","check_type":"wp_package_version","wp_plugin":"safe-login","vulnerable_from":"9.0.0","vulnerable_below":"9.1.2"},
	 {"id":"p-missing","title":"not installed","severity":"critical","check_type":"wp_package_version","wp_plugin":"absent","vulnerable_below":"9"},
	 {"id":"t-theme","title":"Blocks theme below 1.9.6.1","severity":"critical","check_type":"wp_package_version","wp_theme":"blocks","vulnerable_below":"1.9.6.1"},
	 {"id":"p-bad","title":"path tricks","severity":"critical","check_type":"wp_package_version","wp_plugin":"../x","vulnerable_below":"9"}
	]`))
	if strings.Join(skipped, ",") != "p-bad" {
		t.Errorf("skipped %v", skipped)
	}
	var found []string
	ruleScan(&site{Kind: "wordpress", Root: d}, rules, func(f finding) { found = append(found, f.What+" @ "+f.Where+" "+f.Detail) })
	want := []string{"Fast Cache below 6.4 [p-old] @ wp-content/plugins/fast-cache version 6.3.0.1 is installed; fixed in 6.4", "Blocks theme below 1.9.6.1 [t-theme] @ wp-content/themes/blocks version 1.9.6 is installed; fixed in 1.9.6.1"}
	if strings.Join(found, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s", strings.Join(found, "\n"))
	}
}

func TestVersionBelow(t *testing.T) {
	for _, c := range []struct {
		have, fixed string
		want        bool
	}{{"1.7.3", "1.7.4", true}, {"v1.7.4", "1.7.4", false}, {"1.9.10", "1.9.9", false}, {"1.9.9", "1.9.10", true}, {"2.0", "1.20.0", false}, {"1.20", "1.20.0", false}, {"1.19.9-p2", "1.20.0", true}} {
		if got := versionBelow(c.have, c.fixed); got != c.want {
			t.Errorf("versionBelow(%s, %s) = %v", c.have, c.fixed, got)
		}
	}
}
