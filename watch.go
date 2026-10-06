package main

// What the daily health check looks at besides disks and services, because an
// owner assumes someone does: whether backups still run, whether the server ran
// out of memory, PHP out of workers or the database out of connections, and
// whether a site runs software with a known hole. The hub turns the answers
// into alerts (hub/watch.ts evaluate).

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- backups

var backupDirs = []string{
	"/var/backups/sites", "/var/backups", "/backup", "/backups", "/root/backups", "/root/backup",
	"/home/backup", "/home/backups", "/home/*/backups", "/home/*/backup", "/srv/backup", "/srv/backups",
	"/mnt/backup*", "/var/lib/psa/dumps", "/var/www/vhosts/*/backups",
}

var (
	backupFile = regexp.MustCompile(`(?i)\.(sql|sql\.gz|sql\.zst|sql\.bz2|sql\.xz|dump|tar|tar\.gz|tgz|tar\.zst|tzst|tar\.bz2|tar\.xz|zip|7z|xbstream|gz|zst)$`)
	// What the system keeps in /var/backups by itself: not a backup of any site.
	systemBackup = regexp.MustCompile(`^(dpkg\.|apt\.|alternatives\.|passwd|group|shadow|gshadow)`)
	backupTool   = regexp.MustCompile(`(?i)\b(restic|borg|borgmatic|rclone|duplicity|duply|rsnapshot|mysqldump|mariadb-dump|mariabackup|xtrabackup|pg_dump|site-backup|backup)\b`)
)

// backupsFound reports the backup files on this machine (how many, how old the
// newest is, and the ages of the last few runs so the hub can tell their rhythm)
// and any backup program that is scheduled, which may send them straight elsewhere.
func backupsFound(now time.Time) map[string]any {
	dirs := backupDirs
	if !privileged {
		dirs = []string{agentHome + "/backups", agentHome + "/backup", agentHome + "/Backups"}
	}
	var times []time.Time
	newestDir := ""
	var newest time.Time
	seen := map[string]bool{}
	for _, g := range dirs {
		roots, _ := filepath.Glob(g)
		for _, root := range roots {
			if real := realPath(root); seen[real] {
				continue
			} else {
				seen[real] = true
			}
			depth0 := strings.Count(root, "/")
			n := 0
			filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if strings.Count(p, "/")-depth0 > 3 || (p != root && seen[realPath(p)]) {
						return filepath.SkipDir
					}
					return nil
				}
				if n++; n > 20000 {
					return filepath.SkipAll
				}
				if !d.Type().IsRegular() || !backupFile.MatchString(d.Name()) || systemBackup.MatchString(d.Name()) {
					return nil
				}
				if fi, err := d.Info(); err == nil && fi.Size() > 10<<10 {
					times = append(times, fi.ModTime())
					if fi.ModTime().After(newest) {
						newest, newestDir = fi.ModTime(), filepath.Dir(p)
					}
				}
				return nil
			})
		}
	}
	out := map[string]any{"files": len(times)}
	if len(times) > 0 {
		// One run writes several files: files within an hour of each other are one run.
		sort.Slice(times, func(i, j int) bool { return times[i].After(times[j]) })
		var runs []float64
		last := time.Time{}
		for _, t := range times {
			if last.IsZero() || last.Sub(t) > time.Hour {
				runs = append(runs, round1(now.Sub(t).Hours()))
				last = t
			}
			if len(runs) == 8 {
				break
			}
		}
		out["newest_hours"], out["runs_hours_ago"], out["folder"] = runs[0], runs, newestDir
	}
	out["scheduled"] = backupSchedules()
	return out
}

func backupSchedules() []string {
	found := []string{}
	add := func(what string) {
		for _, f := range found {
			if f == what {
				return
			}
		}
		if len(found) < 10 {
			found = append(found, what)
		}
	}
	var crons []string
	if privileged {
		for _, g := range []string{"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/etc/cron.d/*", "/etc/crontab"} {
			m, _ := filepath.Glob(g)
			crons = append(crons, m...)
		}
		for _, g := range []string{"/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.hourly/*"} {
			m, _ := filepath.Glob(g)
			for _, f := range m {
				if t := backupTool.FindString(filepath.Base(f)); t != "" {
					add(strings.ToLower(t) + " (" + f + ")")
				}
			}
		}
	}
	for _, cf := range crons {
		f, err := os.Open(cf)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if t := backupTool.FindString(l); t != "" {
				add(strings.ToLower(t) + " (cron " + filepath.Base(cf) + ")")
			}
		}
		f.Close()
	}
	if !privileged {
		if out, err := exec.Command("crontab", "-l").Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					if t := backupTool.FindString(l); t != "" {
						add(strings.ToLower(t) + " (your crontab)")
					}
				}
			}
		}
		return found
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "systemctl", "list-timers", "--all", "--no-legend", "--plain").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			for _, w := range strings.Fields(l) {
				if strings.HasSuffix(w, ".timer") && backupTool.MatchString(w) && !strings.HasPrefix(w, "dpkg-db-backup") {
					add(w)
				}
			}
		}
	}
	return found
}

// --- out of memory

var oomLine = regexp.MustCompile(`Out of memory: Killed process \d+ \(([^)]+)\)`)

// oomKills: how often the kernel killed a program for lack of memory in the last day, and which.
func oomKills() map[string]any {
	if !privileged {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", "-k", "--since", "-24h", "--no-pager", "-o", "cat", "-g", "Out of memory").Output()
	if err != nil && len(out) == 0 {
		return nil // no journal, or nothing matched
	}
	return countOOM(string(out))
}

func countOOM(log string) map[string]any {
	n := 0
	names := []string{}
	for _, m := range oomLine.FindAllStringSubmatch(log, -1) {
		n++
		names = addOnce(names, m[1])
	}
	if len(names) > 6 {
		names = names[:6]
	}
	return map[string]any{"count": n, "killed": names}
}

// --- PHP out of workers

var fpmLogs = []string{
	"/var/log/php-fpm/*.log", "/var/log/php*-fpm.log", "/var/log/php*/*fpm*.log", "/var/opt/remi/php*/log/php-fpm/*.log",
	"/var/log/plesk-php*-fpm/error.log", "/usr/local/lsws/logs/stderr.log",
}

var fpmFull = regexp.MustCompile(`^\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})\].*\[pool ([^\]]+)\].*max_children`)

// fpmSaturation: how often PHP-FPM hit pm.max_children in the last day, per pool.
// Requests wait or fail while it does.
func fpmSaturation(now time.Time) map[string]int {
	if !privileged {
		return nil
	}
	pools := map[string]int{}
	seen := map[string]bool{}
	for _, g := range fpmLogs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			if seen[realPath(f)] {
				continue
			}
			seen[realPath(f)] = true
			lines, _, err := tailLines(f, 2<<20)
			if err != nil {
				continue
			}
			countFPM(lines, now, pools)
		}
	}
	return pools
}

func countFPM(lines []string, now time.Time, pools map[string]int) {
	for _, l := range lines {
		m := fpmFull.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		// PHP-FPM writes its log in the server's own time zone.
		if t, err := time.ParseInLocation("02-Jan-2006 15:04:05", m[1], time.Local); err == nil && now.Sub(t) <= 24*time.Hour && !t.After(now.Add(time.Hour)) {
			pools[m[2]]++
		}
	}
}

// --- database connections

// dbConnections asks the database, with a site's own credentials, how close it came to its connection limit.
func dbConnections(s *site) map[string]any {
	ask := func(sql string) string {
		b, _ := json.Marshal(map[string]any{"site": s.Root, "sql": sql, "read_only": true, "max_rows": 1})
		res, err := dbQuery(b)
		if err != nil {
			return ""
		}
		if rows := res.(map[string]any)["rows"].([][]string); len(rows) == 1 && len(rows[0]) > 0 {
			return rows[0][len(rows[0])-1]
		}
		return ""
	}
	limit, used := 0, 0
	fmtSscan(ask("SELECT @@max_connections"), &limit)
	fmtSscan(ask("SHOW GLOBAL STATUS LIKE 'Max_used_connections'"), &used)
	if limit == 0 {
		return nil
	}
	return map[string]any{"max_connections": limit, "max_used": used}
}

// --- known holes

// knownHoles runs the hub's vulnerability rules that only read a version or one
// file (no walk of the site, no shell): cheap enough for every day.
func knownHoles(packed string, sites []*site) []map[string]string {
	raw, err := base64.StdEncoding.DecodeString(packed)
	if err != nil || len(raw) == 0 {
		return nil
	}
	rules, _ := parseRules(scramble(raw))
	found := []map[string]string{}
	for _, s := range sites {
		var lock struct {
			Packages []struct{ Name, Version string } `json:"packages"`
		}
		if b, err := os.ReadFile(filepath.Join(s.Root, "composer.lock")); err == nil {
			json.Unmarshal(b, &lock)
		}
		for _, r := range rules {
			if !r.forKind(s.Kind) || len(found) >= 40 {
				continue
			}
			hit := func(where, detail string) {
				found = append(found, map[string]string{"site": s.Root, "id": r.ID, "title": r.Title, "severity": r.Severity, "where": where, "detail": detail})
			}
			switch r.CheckType {
			case "signature_absent":
				for _, sc := range r.scopes {
					if b, err := os.ReadFile(filepath.Join(s.Root, sc)); err == nil && !r.fix.Match(b) {
						hit(sc, "the security fix is not in this file")
					}
				}
			case "composer_package_version":
				for _, p := range lock.Packages {
					if p.Name == r.Package && r.affected(p.Version) {
						hit("composer.lock", fmt.Sprintf("%s %s is installed; fixed in %s", p.Name, p.Version, r.Below))
					}
				}
			case "wp_package_version":
				if have := wpPackageVersion(s.Root, r.Plugin, r.Theme); r.affected(have) {
					hit("wp-content", fmt.Sprintf("version %s is installed; fixed in %s", have, r.Below))
				}
			}
		}
	}
	return found
}
