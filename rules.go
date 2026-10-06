package main

// Rule-based checks for the malware scan. The rules are data sent by the hub
// with each scan (hub/scan_rules.json), so new signatures and vulnerability
// checks need no agent release, and the agent binary holds none of them. They
// travel and rest scrambled: an antivirus tool reading the agent's memory or
// the job folder must not mistake the signatures for the malware they find.
//
// Kinds of rule (check_type): a pattern looked for line by line in files of
// given folders and extensions (the default), signature_absent (a patched file
// must contain the fix), composer_package_version and wp_package_version (an
// installed package, plugin or theme older than the fixed version),
// path_exists (files or folders that should not be there) and host_command (a
// shell check of the server that prints HOSTHIT lines). Rules marked scan_db
// also run over the site's stored content; kinds limits a rule to Magento or
// WordPress sites.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scanRule struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Category   string   `json:"category"` // malware | vulnerability | suspicious
	Severity   string   `json:"severity"` // critical | warning
	CheckType  string   `json:"check_type"`
	Scope      string   `json:"scope"`
	Extensions []string `json:"extensions"`
	Pattern    string   `json:"pattern"`
	Exclude    string   `json:"exclude_pattern"`
	ExcludeDir []string `json:"exclude_dirs"`
	Fix        string   `json:"fix_pattern"`
	Package    string   `json:"composer_name"`
	Plugin     string   `json:"wp_plugin"` // folder under wp-content/plugins
	Theme      string   `json:"wp_theme"`  // folder under wp-content/themes
	Below      string   `json:"vulnerable_below"`
	From       string   `json:"vulnerable_from"` // optional: older versions are not affected
	Kinds      []string `json:"kinds"`           // optional: only for these site kinds (magento, wordpress)
	Names      []string `json:"filename_patterns"`
	Message    string   `json:"path_exists_message"`
	Command    string   `json:"command"`
	RootOnly   bool     `json:"master_only"`
	DB         bool     `json:"scan_db"`
	Files      *bool    `json:"filesystem_scan"`
	Fixing     string   `json:"remediation"`

	re, exclude, fix *regexp.Regexp
	exts             map[string]bool
	scopes           []string
}

func scramble(b []byte) []byte {
	k := []byte("sudowhizzy")
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ k[i%len(k)]
	}
	return out
}

// loadRules reads the scrambled rules file a scan was started with, and removes it.
func loadRules(path string) ([]*scanRule, []string) {
	b, err := os.ReadFile(path)
	os.Remove(path)
	if err != nil {
		return nil, nil
	}
	return parseRules(scramble(b))
}

// parseRules compiles the rules; the ones this agent cannot use are named in skipped.
func parseRules(plain []byte) (rules []*scanRule, skipped []string) {
	var all []*scanRule
	if json.Unmarshal(plain, &all) != nil {
		return nil, []string{"the rules could not be read"}
	}
	for _, r := range all {
		ok := true
		compile := func(p string) *regexp.Regexp {
			if p == "" {
				return nil
			}
			re, err := regexp.Compile(p)
			if err != nil {
				ok = false
			}
			return re
		}
		r.re, r.exclude, r.fix = compile(r.Pattern), compile(r.Exclude), compile(r.Fix)
		switch r.CheckType {
		case "":
			ok = ok && r.re != nil
		case "signature_absent":
			ok = ok && r.fix != nil && r.Scope != ""
		case "composer_package_version":
			ok = ok && r.Package != "" && r.Below != ""
		case "wp_package_version":
			ok = ok && (r.Plugin != "") != (r.Theme != "") && r.Below != "" && !strings.ContainsAny(r.Plugin+r.Theme, "/.")
		case "path_exists":
			ok = ok && len(r.Names) > 0
		case "host_command":
			ok = ok && r.Command != ""
		default:
			ok = false
		}
		if !ok || r.ID == "" {
			skipped = append(skipped, r.ID)
			continue
		}
		r.exts = map[string]bool{}
		for _, e := range r.Extensions {
			r.exts["."+strings.ToLower(strings.TrimPrefix(e, "."))] = true
		}
		r.scopes = strings.Fields(r.Scope)
		rules = append(rules, r)
	}
	return rules, skipped
}

func (r *scanRule) sev() string {
	switch r.Severity {
	case "critical":
		return "high"
	case "warning":
		return "medium"
	}
	return "low"
}

func (r *scanRule) finding(where, detail string) finding {
	what := r.Title
	if r.Category != "" {
		what = r.Category + ": " + what
	}
	if r.Fixing != "" {
		detail = strings.TrimSpace(detail + "\nWhat to do: " + r.Fixing)
	}
	return finding{Severity: r.sev(), What: what + " [" + r.ID + "]", Where: where, Detail: detail}
}

// inScope: rel is a path inside the site; a scope of "." is the whole site.
func (r *scanRule) inScope(rel string) bool {
	for _, sc := range r.scopes {
		if !strings.HasPrefix(sc, "/") && (sc == "." || rel == sc || strings.HasPrefix(rel, sc+"/")) {
			return true
		}
	}
	return false
}

func (r *scanRule) skipsDir(rel string) bool {
	for _, d := range r.ExcludeDir {
		if strings.Contains("/"+rel+"/", "/"+d+"/") {
			return true
		}
	}
	return false
}

func (r *scanRule) forKind(kind string) bool {
	for _, k := range r.Kinds {
		if k == kind {
			return true
		}
	}
	if len(r.Kinds) > 0 {
		return false
	}
	// A rule that names no kind was written with Magento and WordPress shops in
	// mind. The other kinds get the ones that look for malware or at the server
	// itself; the tidiness and patch rules would only raise false alarms there.
	return kind == "magento" || kind == "wordpress" || r.Category == "malware" || r.CheckType == "host_command"
}

// affected: the installed version is one the rule names as vulnerable.
func (r *scanRule) affected(have string) bool {
	return have != "" && versionBelow(have, r.Below) && (r.From == "" || !versionBelow(have, r.From))
}

var wpVersionHeader = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:[ \t]*([0-9][0-9A-Za-z.+-]*)`)

// wpPackageVersion reads the version a plugin's main file or a theme's style.css declares.
func wpPackageVersion(root, plugin, theme string) string {
	var files []string
	if theme != "" {
		files = []string{filepath.Join(root, "wp-content/themes", theme, "style.css")}
	} else {
		files, _ = filepath.Glob(filepath.Join(root, "wp-content/plugins", plugin, "*.php"))
	}
	for _, f := range files {
		head := readHead(f, 8192)
		if theme == "" && !strings.Contains(head, "Plugin Name:") {
			continue
		}
		if m := wpVersionHeader.FindStringSubmatch(head); m != nil {
			return m[1]
		}
	}
	return ""
}

func (r *scanRule) readsFiles() bool { return r.CheckType == "" && (r.Files == nil || *r.Files) }

// Dotted versions, numbers compared as numbers: 1.9.10 is newer than 1.9.9.
func versionBelow(have, fixed string) bool {
	num := func(v string) []int {
		var out []int
		for _, p := range strings.FieldsFunc(strings.TrimPrefix(strings.ToLower(v), "v"), func(c rune) bool { return c < '0' || c > '9' }) {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	a, b := num(have), num(fixed)
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

const (
	ruleFileMax  = 4 << 20
	ruleHitsMax  = 8 // findings per rule, then a count
	ruleScanTime = 15 * time.Minute
)

type ruleReport struct {
	Rules   int      `json:"rules"`
	Files   int      `json:"files_read"`
	Skipped []string `json:"rules_not_run,omitempty"`
	Partial string   `json:"partial,omitempty"`
}

// ruleScan runs every rule against one site and reports through add.
func ruleScan(s *site, rules []*scanRule, add func(finding)) ruleReport {
	var mine []*scanRule
	for _, r := range rules {
		if r.forKind(s.Kind) {
			mine = append(mine, r)
		}
	}
	rules = mine
	rep := ruleReport{Rules: len(rules)}
	deadline := time.Now().Add(ruleScanTime)
	var mu sync.Mutex
	hits := map[string]int{}
	report := func(r *scanRule, where, detail string) {
		mu.Lock()
		defer mu.Unlock()
		hits[r.ID]++
		if hits[r.ID] <= ruleHitsMax {
			add(r.finding(where, detail))
		}
	}

	var fileRules, pathRules []*scanRule
	for _, r := range rules {
		switch {
		case r.readsFiles():
			fileRules = append(fileRules, r)
		case r.CheckType == "path_exists":
			pathRules = append(pathRules, r)
		}
	}

	// Files: one walk of the site, each file read once for all the rules that want it.
	type job struct {
		path, rel string
		rules     []*scanRule
	}
	work := make(chan job, 64)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				b, err := os.ReadFile(j.path)
				if err != nil {
					continue
				}
				done := map[*scanRule]bool{}
				for n, line := range bytes.Split(b, []byte("\n")) {
					if len(done) == len(j.rules) {
						break
					}
					for _, r := range j.rules {
						if done[r] || !r.re.Match(line) {
							continue
						}
						if r.exclude != nil && r.exclude.MatchString(j.rel+":"+string(line)) {
							continue
						}
						done[r] = true
						report(r, fmt.Sprintf("%s:%d", j.rel, n+1), truncate(strings.TrimSpace(string(line)), 240))
					}
				}
			}
		}()
	}
	// Folders that are caches, generated code or tests are not read, unless a rule names
	// a folder inside one (var/report): then only that part is.
	skip := []string{"var", "generated", ".git", "node_modules", "dev/tests", "pub/static/_cache"}
	within := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	var named []string
	for _, r := range rules {
		for _, sc := range r.scopes {
			for _, k := range skip {
				if within(sc, k) {
					named = append(named, sc)
				}
			}
		}
	}
	skipped := func(rel string) bool {
		under := false
		for _, k := range skip {
			under = under || within(rel, k)
		}
		if !under {
			return false
		}
		for _, sc := range named {
			if within(sc, rel) || within(rel, sc) {
				return false
			}
		}
		return true
	}
	walk := func(root string, rel func(p string) string, wants func(r *scanRule, rel string) bool) {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if time.Now().After(deadline) {
				rep.Partial = "stopped after 15 minutes; not every file was read"
				return filepath.SkipAll
			}
			rl := rel(p)
			for _, r := range pathRules {
				if !wants(r, rl) || (r.exclude != nil && r.exclude.MatchString(rl+"/")) {
					continue
				}
				for _, pat := range r.Names {
					if ok, _ := filepath.Match(pat, d.Name()); ok {
						msg := r.Message
						if msg == "" {
							msg = "should not be inside the site's folder"
						}
						report(r, rl, msg)
						break
					}
				}
			}
			if d.IsDir() && skipped(rl) {
				return filepath.SkipDir // named above if a rule looks for it; never read
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			var todo []*scanRule
			for _, r := range fileRules {
				if wants(r, rl) && (len(r.exts) == 0 || r.exts[ext]) && !r.skipsDir(rl) {
					todo = append(todo, r)
				}
			}
			if len(todo) == 0 {
				return nil
			}
			if fi, err := d.Info(); err != nil || fi.Size() > ruleFileMax || fi.Size() == 0 {
				return nil
			}
			rep.Files++
			work <- job{p, rl, todo}
			return nil
		})
	}
	walk(s.Root, func(p string) string { return strings.TrimPrefix(strings.TrimPrefix(p, s.Root), "/") }, func(r *scanRule, rel string) bool { return r.inScope(rel) })
	// Folders outside the site that a rule names (system PHP libraries): only root can vouch for those.
	if privileged {
		outside := map[string]bool{}
		for _, r := range fileRules {
			for _, sc := range r.scopes {
				if strings.HasPrefix(sc, "/") {
					outside[sc] = true
				}
			}
		}
		for root := range outside {
			inside := false // a file or folder under another one that is walked anyway
			for other := range outside {
				inside = inside || (other != root && within(root, other))
			}
			if inside {
				continue
			}
			walk(root, func(p string) string { return p }, func(r *scanRule, p string) bool {
				for _, sc := range r.scopes {
					if strings.HasPrefix(sc, "/") && (p == sc || strings.HasPrefix(p, sc+"/")) {
						return true
					}
				}
				return false
			})
		}
	}
	close(work)
	wg.Wait()

	// A security patch that is not there, and packages older than their fixed version.
	var lock struct {
		Packages []struct{ Name, Version string } `json:"packages"`
	}
	if b, err := os.ReadFile(filepath.Join(s.Root, "composer.lock")); err == nil {
		json.Unmarshal(b, &lock)
	}
	for _, r := range rules {
		switch r.CheckType {
		case "signature_absent":
			for _, sc := range r.scopes {
				if b, err := os.ReadFile(filepath.Join(s.Root, sc)); err == nil && !r.fix.Match(b) {
					report(r, sc, "the security fix is not in this file")
				}
			}
		case "composer_package_version":
			for _, p := range lock.Packages {
				if p.Name == r.Package && r.affected(p.Version) {
					report(r, "composer.lock", fmt.Sprintf("%s %s is installed; fixed in %s", p.Name, p.Version, r.Below))
				}
			}
		case "wp_package_version":
			if have := wpPackageVersion(s.Root, r.Plugin, r.Theme); r.affected(have) {
				report(r, filepath.Join("wp-content", map[bool]string{true: "themes", false: "plugins"}[r.Theme != ""], r.Plugin+r.Theme), fmt.Sprintf("version %s is installed; fixed in %s", have, r.Below))
			}
		case "host_command":
			if r.RootOnly && !privileged {
				rep.Skipped = append(rep.Skipped, r.ID+" (needs a root agent)")
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			cmd := exec.CommandContext(ctx, "bash", "-c", r.Command)
			cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SITEROOT="+s.Root)
			if s.Owner != "" && s.Owner != "root" {
				cmd.Env = append(cmd.Env, "USERACCT="+s.Owner) // look at this site's account, not the whole server
			}
			out, _ := cmd.Output()
			cancel()
			for _, l := range strings.Split(string(out), "\n") {
				if f := strings.SplitN(l, "|", 4); len(f) == 4 && f[0] == "HOSTHIT" {
					report(r, f[2], truncate(f[3], 400))
				}
			}
		}
	}

	// Stored content: skimmers live in CMS blocks, pages and configuration as often as in files.
	if s.db != nil && s.db.Name != "" {
		ruleScanDB(s, rules, report)
	}
	for _, r := range rules {
		if n := hits[r.ID]; n > ruleHitsMax {
			add(finding{Severity: "low", What: fmt.Sprintf("%d more matches of [%s] not listed", n-ruleHitsMax, r.ID), Where: ""})
		}
	}
	return rep
}

func ruleScanDB(s *site, rules []*scanRule, report func(r *scanRule, where, detail string)) {
	var content, records []*scanRule
	for _, r := range rules {
		if r.DB && r.re != nil {
			if r.Files != nil && !*r.Files {
				records = append(records, r)
			} else {
				content = append(content, r)
			}
		}
	}
	query := func(sql string, rows int) [][]string {
		b, _ := json.Marshal(map[string]any{"site": s.Root, "sql": sql, "read_only": true, "max_rows": rows})
		res, err := dbQuery(b)
		if err != nil {
			return nil
		}
		return res.(map[string]any)["rows"].([][]string)
	}
	p := s.db.Prefix
	var sources []string
	if s.Kind == "magento" {
		sources = []string{
			fmt.Sprintf("SELECT CONCAT('cms_block ', identifier), content FROM %scms_block", p),
			fmt.Sprintf("SELECT CONCAT('cms_page ', identifier), content FROM %scms_page", p),
			fmt.Sprintf("SELECT CONCAT('core_config_data ', path), value FROM %score_config_data WHERE CHAR_LENGTH(value) > 40 AND (value LIKE '%%<%%' OR value LIKE '%%(%%')", p),
		}
	} else if s.Kind == "wordpress" {
		sources = []string{
			fmt.Sprintf("SELECT CONCAT('option ', option_name), option_value FROM %soptions WHERE option_value LIKE '%%<script%%' AND option_name NOT LIKE '\\_transient%%'", p),
			fmt.Sprintf("SELECT CONCAT('post ', ID), post_content FROM %sposts WHERE post_content LIKE '%%<script%%' AND post_status <> 'trash'", p),
		}
	}
	if len(content) > 0 {
		for _, sql := range sources {
			for _, row := range query(sql, 1000) {
				if len(row) != 2 {
					continue
				}
				for _, r := range content {
					for _, line := range strings.Split(row[1], "\n") {
						if r.re.MatchString(line) && (r.exclude == nil || !r.exclude.MatchString(row[0]+":"+line)) {
							report(r, "database "+s.db.Name+": "+row[0], truncate(strings.TrimSpace(line), 240))
							break
						}
					}
				}
			}
		}
	}
	// Rules about what customers typed in: order addresses (Magento).
	if s.Kind == "magento" {
		for _, r := range records {
			lit := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(r.Pattern)
			fields := "CONCAT_WS(' ', firstname, lastname, company, street, city, region, postcode, telephone)"
			for _, row := range query(fmt.Sprintf("SELECT CONCAT('order address ', entity_id, ' of order ', parent_id), %s FROM %ssales_order_address WHERE %s REGEXP '%s' LIMIT 20", fields, p, fields, lit), 20) {
				if len(row) == 2 {
					report(r, "database "+s.db.Name+": "+row[0], truncate(row[1], 240))
				}
			}
		}
	}
}
