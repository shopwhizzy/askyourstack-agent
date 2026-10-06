package main

import (
	"encoding/base64"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestBackupsFound(t *testing.T) {
	d := t.TempDir()
	now := time.Now()
	old := backupDirs
	backupDirs = []string{d + "/backups", d + "/var-backups", d + "/none*"}
	defer func() { backupDirs = old }()
	big := string(make([]byte, 20<<10))
	file := func(path string, hoursAgo float64) {
		put(t, path, big)
		at := now.Add(-time.Duration(hoursAgo * float64(time.Hour)))
		os.Chtimes(path, at, at)
	}
	// Three nightly runs, each a database and a files archive minutes apart.
	file(d+"/backups/2026-10-05/shop.sql.gz", 30)
	file(d+"/backups/2026-10-05/shop.tar.gz", 29.9)
	file(d+"/backups/2026-10-04/shop.sql.gz", 54)
	file(d+"/backups/2026-10-03/shop.sql.gz", 78)
	file(d+"/backups/notes.txt", 1)               // not a backup
	file(d+"/var-backups/dpkg.status.0.gz", 2)    // the system's own
	put(t, d+"/backups/2026-10-05/tiny.sql", "x") // too small to be one
	got := backupsFound(now)
	if got["files"] != 4 || got["folder"] != d+"/backups/2026-10-05" || !reflect.DeepEqual(got["runs_hours_ago"], []float64{29.9, 54, 78}) {
		t.Errorf("got %+v", got)
	}
	backupDirs = []string{d + "/none*"}
	if got := backupsFound(now); got["files"] != 0 || got["newest_hours"] != nil {
		t.Errorf("empty: %+v", got)
	}
}

func TestCountOOM(t *testing.T) {
	log := "Out of memory: Killed process 812 (mariadbd) total-vm:3355444kB, anon-rss:1612345kB\nsomething else\nOut of memory: Killed process 99 (php-fpm) total-vm:1kB\nOut of memory: Killed process 100 (php-fpm) total-vm:1kB\n"
	got := countOOM(log)
	if got["count"] != 3 || !reflect.DeepEqual(got["killed"], []string{"mariadbd", "php-fpm"}) {
		t.Errorf("got %+v", got)
	}
	if got := countOOM(""); got["count"] != 0 {
		t.Errorf("empty: %+v", got)
	}
}

func TestCountFPM(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	lines := []string{
		"[05-Oct-2026 11:58:01] WARNING: [pool shop] server reached pm.max_children setting (20), consider raising it",
		"[05-Oct-2026 03:10:44] WARNING: [pool shop] server reached pm.max_children setting (20), consider raising it",
		"[04-Oct-2026 13:00:00] WARNING: [pool blog] server reached max_children setting (5), consider raising it",
		"[03-Oct-2026 09:00:00] WARNING: [pool shop] server reached pm.max_children setting (20), consider raising it", // older than a day
		"[05-Oct-2026 11:00:00] NOTICE: [pool shop] child 123 started",
	}
	pools := map[string]int{}
	countFPM(lines, now, pools)
	if !reflect.DeepEqual(pools, map[string]int{"shop": 2, "blog": 1}) {
		t.Errorf("got %v", pools)
	}
}

func TestKnownHoles(t *testing.T) {
	d := t.TempDir()
	put(t, d+"/wp-content/plugins/fast-cache/fast-cache.php", "<?php\n/**\n * Plugin Name: Fast Cache\n * Version: 6.3\n */\n")
	put(t, d+"/vendor/x/P.php", "<?php // unpatched")
	put(t, d+"/app/code/a.php", "<?php zz_marker(1);")
	rules := `[
	 {"id":"p","title":"Fast Cache below 6.4","severity":"critical","check_type":"wp_package_version","wp_plugin":"fast-cache","vulnerable_below":"6.4","kinds":["wordpress"]},
	 {"id":"m","title":"Magento only","severity":"critical","check_type":"signature_absent","scope":"vendor/x/P.php","fix_pattern":"fixed","kinds":["magento"]},
	 {"id":"s","title":"patch missing","severity":"warning","check_type":"signature_absent","scope":"vendor/x/P.php","fix_pattern":"fixed"},
	 {"id":"walk","title":"needs a walk","severity":"critical","scope":"app","extensions":["php"],"pattern":"zz_marker"},
	 {"id":"sh","title":"needs a shell","severity":"critical","check_type":"host_command","command":"echo 'HOSTHIT|sh|x|y'"}
	]`
	got := knownHoles(base64.StdEncoding.EncodeToString(scramble([]byte(rules))), []*site{{Kind: "wordpress", Root: d}})
	if len(got) != 2 || got[0]["id"] != "p" || got[0]["detail"] != "version 6.3 is installed; fixed in 6.4" || got[1]["id"] != "s" || got[1]["severity"] != "warning" {
		t.Errorf("got %+v", got)
	}
	if got := knownHoles("", nil); got != nil {
		t.Errorf("no rules: %+v", got)
	}
}
