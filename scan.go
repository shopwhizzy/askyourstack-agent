package main

// A quick, dependency-free malware check for Magento and WordPress sites:
// backdoor patterns in PHP, PHP where only uploads belong, disguised and
// hidden PHP, recently changed code, scripts injected through the database,
// suspicious cron entries and processes. It finds the common cases; it is not
// a full antivirus (ClamAV or maldet can be installed for that).

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type finding struct {
	Severity string `json:"severity"` // high | medium | low
	What     string `json:"what"`
	Where    string `json:"where"`
	Detail   string `json:"detail,omitempty"`
}

// The patterns are stored scrambled (sig) so the agent binary never contains
// malware names or backdoor code patterns in readable form: antivirus tools such
// as Sansec ecomscan flag any process holding them. The readable pattern is in
// the comment above each one; scripts/sig.py scrambles a new one.
func sig(h string) *regexp.Regexp {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	k := []byte("sudowhizzy")
	for i := range b {
		b[i] ^= k[i%len(k)]
	}
	return regexp.MustCompile(string(b))
}

var phpBad = []struct {
	re   *regexp.Regexp
	what string
	sev  string
}{
	// (?i)\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode)\s*\(
	{sig("5b4a0d462b0a0c0c1b152f064e335f341a50521b1206015943370d1f1916171018080d01071c1618071018080d1d071915140307011c04140e001e1c101a000a0b1b1d08250b1c01555c0b1b1d08081c05090c0a0f5a0b1314050114131a05040d1f191617104d3304423552"), "eval of decoded data", "high"},
	// (?i)\b(assert|eval|create_function)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)
	{sig("5b4a0d462b0a411b090a16071013121e0816061a0110051b12370f0f141a071c0b015e341a5026512f064e335337412a352a2709232a23143b3f2b2c3626301334272631333c0f26213d212d3b53"), "runs code straight from a request", "high"},
	// (?i)\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(
	{sig("5b4a0d462b4c36522a3620211828323c15283f282630373b0b2b26353130365c381c5d34322124252e281f5e5b5c590726242f064e335f"), "calls a function named by a request parameter", "high"},
	// (?i)\b(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)
	{sig("5b4a0d462b0a4109030a0710091304000c161626160d010c0b180809090d1b07111312100c1906091c0501010b181b1519261c0501015e341a5026512f064e335337412a352a2709232a23143b3f2b2c3626301334272631333c5a"), "runs shell commands from a request", "high"},
	// Go's regexp has no backreferences, so the usual pattern delimiters are listed one by one.
	// (?i)preg_replace\s*\(\s*['"](/[^/]*/|#[^#]*#|~[^~]*~|\|[^|]*\||![^!]*!|@[^@]*@)[a-z]*e[a-z]*['"]
	{sig("5b4a0d46071a0c1d250b1605080e140d350950255b2917452c4f4b275256282b4b325d471559212750284e4c0b1632240424590b18330b33370627532f09184e2c36482750580f353f313735433a532212581e325d0d321b57032e5f3f485535"), "preg_replace with the /e modifier (only runs on PHP 5)", "medium"},
	// (?i)\b(file_put_contents|fwrite)\s*\([^;]{0,200}base64_decode
	{sig("5b4a0d462b0a411c1315162a141a03370a15140d161b101c0b0e1e08130d165c381c5d34412124422e0e54434558590718180010525b280c0c19151d16"), "writes decoded data to a file", "medium"},
	// (?i)(\\x[0-9a-f]{2}){20,}
	{sig("5b4a0d465f34350221495e4c0542113512480750084754430a"), "long hex-escaped string", "medium"},
	// [A-Za-z0-9+/]{1000,}={0,2}
	{sig("283449351645134a5740585a39144658594a56044e0e54434515"), "very long base64 blob", "medium"},
	// (?i)\b(c99shell|r57shell|b374k|FilesMan|IndoXploit|WSOsetcookie|wso_version)\b
	{sig("5b4a0d462b0a41194340001d01031b141b4f4d0a1b1008030b0a5a4d4e120f330d03121b241b14053a1b00002f180515130d0f223720040d1d191516181c0113001b06250c1c01060d0019413518"), "known web shell name", "high"},
}

// Files without any of these words, and short, cannot match the PHP patterns below.
// (?i)eval|assert|create_function|\$_(POST|GET|REQUEST|COOKIE|SERVER)|preg_replace|base64|\\x[0-9a-f]{2}|c99shell|r57shell|b374k|FilesMan|IndoXploit|WSOsetcookie|wso_version|file_put_contents|fwrite
var phpTell = sig("5b4a0d46121e081606180006011d03140a081f1807103b0902060a0e13161d09384b28403935292d0f32213b0b3a2c2b2f3c2021182c382722333f0520303639323a40060a0b16123b1d1218051b191c0f17051c125e5d0626250b2e54424e09441c27024108180c4e511a121f151f09165a401b011f16150f1757584303153c13151606290e191420141e162b0508001e1c152d29360010100c180702131f0504060b30010d1b0913161d0902061b0d360a0f0d2c160b01030d070e090515021606030d")

var jsBad = []struct {
	re   *regexp.Regexp
	what string
}{
	// (?i)atob\(\s*['"][A-Za-z0-9+/=]{80,}['"]\s*\)
	{sig("5b4a0d46161c061826512f064e34504a34213b54291449154745505155442e0e5c5f5b15325d58242f064e335e"), "decodes a long hidden string in JavaScript"},
	// (?i)(String\.fromCharCode\([0-9,\s]{120,}\))
	{sig("5b4a0d465f3b1d08131714294a0905070439121801360b0b123441214a544a59381c2a1358484a550e294d46"), "builds hidden JavaScript from character codes"},
	// (?i)new\s+WebSocket\(\s*['"]wss?://
	{sig("5b4a0d46190d1e2609522410063c180b021f0e255b2917452c4f4b270d0a004a5e4058"), "opens a WebSocket (some skimmers send card data this way)"},
	// (?i)(cc_number|cardnumber|card_number|cvv|cvc)[^\n]{0,200}(fetch|XMLHttpRequest|sendBeacon|\.send\()
	{sig("5b4a0d465f0b0a25140c1e17011d0b0b08081e170618060a05140a1b081d2c1b1102150d1b06190f050907191441322426172e0e544345585907521f160107070b302436320d0705360a061d0c090e0500100a0b350d081915170f294a1c12060d265250"), "reads card fields and sends data out"},
}

var scriptTag = regexp.MustCompile(`(?is)<script[^>]*>.{0,300}|<script[^>]+src\s*=\s*['"]?[^'" >]+`)

// malwareScan starts the scan as a background job: on a big shop it takes longer
// than an AI client waits for one tool call.
func malwareScan(raw json.RawMessage) (any, error) {
	var a struct {
		Site  string `json:"site"`
		Days  int    `json:"days"`
		Rules string `json:"rules"` // from the hub: base64 of the scrambled rules (rules.go)
	}
	json.Unmarshal(raw, &a)
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if a.Days <= 0 {
		a.Days = 14
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("%s scan %s %d", shellQuote(self), shellQuote(s.Root), a.Days)
	// The rules wait in a private file, still scrambled, for the scan to pick up and delete.
	if rules, err := base64.StdEncoding.DecodeString(a.Rules); err == nil && len(rules) > 0 {
		if f, err := os.CreateTemp("", "sw-rules-*"); err == nil {
			os.Chmod(f.Name(), 0o600)
			f.Write(rules)
			f.Close()
			command += " " + shellQuote(f.Name())
		}
	}
	b, _ := json.Marshal(map[string]string{"command": command, "name": "malware-scan"})
	res, err := jobStart(b)
	if err != nil {
		return nil, err
	}
	r := res.(map[string]any)
	r["next"] = "The scan runs in the background (about a minute per 40,000 files). Call job_output with this job_id and offset 0 until status is finished; the output is the JSON report."
	return r, nil
}

func malwareScanNow(raw json.RawMessage) (any, error) {
	var a struct {
		Site      string `json:"site"`
		Days      int    `json:"days"`
		RulesFile string `json:"rules_file"`
	}
	json.Unmarshal(raw, &a)
	if a.Days <= 0 {
		a.Days = 14
	}
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	var found []finding
	add := func(f finding) {
		if len(found) < 150 {
			found = append(found, f)
		}
	}
	recent := time.Now().Add(-time.Duration(a.Days) * 24 * time.Hour)
	var recentCode []string
	scanned := 0
	type candidate struct {
		path, rel string
		php       bool
	}
	var candidates []candidate
	start := time.Now()

	// Where uploads go and which caches hold compiled code depends on the kind of site (kinds.go).
	uploadDirs := kindOf(s.Kind).Uploads
	skipDirs := append([]string{".git/", "node_modules/"}, kindOf(s.Kind).Skip...)
	// Test fixtures legitimately hold PHP in odd places; malware there would never run.
	isTestPath := func(rel string) bool {
		return strings.Contains(rel, "/Test/") || strings.Contains(rel, "/Tests/") || strings.Contains(rel, "/tests/") || strings.Contains(rel, "/testsuite/") || strings.Contains(rel, "/Fixtures/") || strings.Contains(rel, "/fixtures/") || strings.Contains(rel, "/_files/")
	}
	devDotfile := regexp.MustCompile(`^\.(php[-_]cs[-_]fixer|php_cs|phpstan|psalm|phpcs|phpunit|rector|phpstorm\.meta|ht\.router\.php$)`)

	filepath.WalkDir(s.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, s.Root+"/")
		if d.IsDir() {
			for _, sd := range skipDirs {
				if rel+"/" == sd {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))
		isPHP := ext == ".php" || ext == ".phtml" || ext == ".php5" || ext == ".php7" || ext == ".phar" || ext == ".inc"
		inUploads := false
		for _, u := range uploadDirs {
			if strings.HasPrefix(rel, u) {
				inUploads = true
			}
		}
		fi, _ := d.Info()
		if isPHP && inUploads && !strings.HasSuffix(rel, "/index.php") {
			add(finding{"high", "PHP file in an upload folder", rel, ""})
		}
		if isTestPath(rel) {
			return nil
		}
		if isPHP && strings.HasPrefix(name, ".") && !devDotfile.MatchString(name) {
			add(finding{"high", "hidden PHP file", rel, ""})
		}
		if fi != nil && fi.ModTime().After(recent) && (isPHP || ext == ".js") && !strings.HasPrefix(rel, "pub/static/") {
			recentCode = append(recentCode, rel)
		}
		// Disguised PHP: images, icons or text files holding PHP code.
		disguise := ext == ".ico" || ext == ".png" || ext == ".jpg" || ext == ".gif" || ext == ".svg" || (ext == ".txt" && !strings.HasPrefix(rel, "vendor/"))
		if !isPHP && disguise && fi != nil && fi.Size() < 2<<20 {
			if head := readHead(p, 4096); strings.Contains(head, "<?php") {
				add(finding{"high", "PHP code inside a " + ext + " file", rel, ""})
			}
		}
		checkJS := ext == ".js" && fi != nil && fi.ModTime().After(recent) && fi.Size() < 2<<20 && !strings.HasPrefix(rel, "pub/static/")
		if (isPHP || checkJS) && fi != nil && fi.Size() <= 4<<20 {
			candidates = append(candidates, candidate{p, rel, isPHP})
		}
		return nil
	})

	// Read and match in parallel; most files are rejected by a cheap substring test first.
	work := make(chan candidate)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				b, err := os.ReadFile(c.path)
				if err != nil {
					continue
				}
				var hits []finding
				if c.php {
					if !phpTell.Match(b) && len(b) < 1000 {
						continue
					}
					text := string(b)
					for _, r := range phpBad {
						if r.sev == "medium" && (strings.HasPrefix(c.rel, "vendor/") || strings.Contains(c.rel, "/vendor/")) {
							continue // vendor code legitimately holds long base64 and hex (fonts, data)
						}
						if loc := r.re.FindStringIndex(text); loc != nil {
							hits = append(hits, finding{r.sev, r.what, fmt.Sprintf("%s:%d", c.rel, 1+strings.Count(text[:loc[0]], "\n")), snippet(text, loc)})
						}
					}
				} else {
					text := string(b)
					for _, r := range jsBad {
						if loc := r.re.FindStringIndex(text); loc != nil {
							hits = append(hits, finding{"medium", r.what + " (changed in the last " + fmt.Sprint(a.Days) + " days)", fmt.Sprintf("%s:%d", c.rel, 1+strings.Count(text[:loc[0]], "\n")), snippet(text, loc)})
						}
					}
				}
				mu.Lock()
				for _, h := range hits {
					add(h)
				}
				mu.Unlock()
			}
		}()
	}
	for _, c := range candidates {
		work <- c
	}
	close(work)
	wg.Wait()
	scanned = len(candidates)

	sort.Strings(recentCode)
	if len(recentCode) > 0 {
		shown := recentCode
		if len(shown) > 40 {
			shown = shown[:40]
		}
		add(finding{"low", fmt.Sprintf("%d PHP/JS files changed in the last %d days (normal after updates or deploys; check any you did not expect)", len(recentCode), a.Days), "", strings.Join(shown, "\n")})
	}

	// The database: skimmers are often stored in configuration or content.
	if s.db != nil && s.db.Name != "" && (s.Kind == "magento" || s.Kind == "wordpress") {
		var checks []struct{ sql, what string }
		p := s.db.Prefix
		if s.Kind == "magento" {
			checks = append(checks,
				struct{ sql, what string }{fmt.Sprintf("SELECT path, scope_id, value FROM %score_config_data WHERE value LIKE '%%<script%%' OR path IN ('design/head/includes','design/footer/absolute_footer','design/head/miscellaneous_scripts')", p), "script in Magento configuration (design/head/includes and similar)"},
				struct{ sql, what string }{fmt.Sprintf("SELECT identifier, LEFT(content, 300) FROM %scms_block WHERE content LIKE '%%<script%%' UNION ALL SELECT identifier, LEFT(content, 300) FROM %scms_page WHERE content LIKE '%%<script%%'", p, p), "script in a CMS block or page"},
				struct{ sql, what string }{fmt.Sprintf("SELECT username, email, created, logdate FROM %sadmin_user WHERE created > NOW() - INTERVAL %d DAY", p, a.Days), "admin user created recently"},
			)
		} else {
			checks = append(checks,
				struct{ sql, what string }{fmt.Sprintf("SELECT option_name, LEFT(option_value, 300) FROM %soptions WHERE option_value LIKE '%%<script%%' AND option_name NOT LIKE '\\_transient%%'", p), "script stored in WordPress options"},
				struct{ sql, what string }{fmt.Sprintf("SELECT ID, post_type, post_title, post_modified FROM %sposts WHERE post_content LIKE '%%<script%%src%%' AND post_status <> 'trash' LIMIT 50", p), "external script in a post or page"},
				struct{ sql, what string }{fmt.Sprintf("SELECT u.user_login, u.user_email, u.user_registered FROM %susers u JOIN %susermeta m ON m.user_id = u.ID AND m.meta_key = '%scapabilities' WHERE m.meta_value LIKE '%%administrator%%'", p, p, p), "administrator account (check you know each one)"},
			)
		}
		for _, c := range checks {
			b, _ := json.Marshal(map[string]any{"site": s.Root, "sql": c.sql, "read_only": true, "max_rows": 50})
			res, err := dbQuery(b)
			if err != nil {
				add(finding{"low", "could not check: " + c.what, "database", err.Error()})
				continue
			}
			rows := res.(map[string]any)["rows"].([][]string)
			for _, r := range rows {
				row := strings.Join(r, " | ")
				sev := "medium"
				if strings.Contains(c.what, "administrator account") {
					sev = "low"
				} else if scriptTag.MatchString(row) {
					sev = "high"
				} else if strings.Contains(c.what, "configuration") && strings.TrimSpace(strings.Join(r[2:], "")) == "" {
					continue // empty design fields are normal
				}
				add(finding{sev, c.what, "database " + s.db.Name, truncate(row, 400)})
			}
		}
	}

	// Cron entries that download or decode code.
	// (?i)(curl|wget)[^#\n]*\|\s*(ba)?sh|base64\s+(-d|--decode)|/dev/shm/|/tmp/\.[^/\s]+|\beval\b
	cronBad := sig("5b4a0d465f0b1c0816050412011b5e33375926172e5f38132b1b435218185a4a17070b0a08091f4f472917445f450d06575417100700130d4006551d16034b1c1f054606550d1e054b3359333755260a2e5e1833150d1f1b162511")
	var cronFiles []string
	for _, g := range []string{"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/etc/cron.d/*", "/etc/crontab"} {
		m, _ := filepath.Glob(g)
		cronFiles = append(cronFiles, m...)
	}
	for _, cf := range cronFiles {
		f, err := os.Open(cf)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			if l := sc.Text(); !strings.HasPrefix(strings.TrimSpace(l), "#") && cronBad.MatchString(l) {
				add(finding{"high", "suspicious cron entry", fmt.Sprintf("%s:%d", cf, n), truncate(l, 300)})
			}
		}
		f.Close()
	}

	// Processes running from temporary folders or from deleted files.
	procs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, pe := range procs {
		exe, err := os.Readlink(pe)
		if err != nil {
			continue
		}
		if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/dev/shm/") || strings.HasPrefix(exe, "/var/tmp/") || (strings.HasSuffix(exe, " (deleted)") && !strings.Contains(exe, "/usr/")) {
			cmdline, _ := os.ReadFile(filepath.Join(filepath.Dir(pe), "cmdline"))
			add(finding{"high", "process running from a temporary or deleted file", exe, truncate(strings.ReplaceAll(string(cmdline), "\x00", " "), 200)})
		}
	}

	// WordPress core and plugins against wordpress.org checksums, when wp-cli is there.
	if s.Kind == "wordpress" {
		if s.has("wp") {
			for _, sub := range [][]string{{"core", "verify-checksums"}, {"plugin", "verify-checksums", "--all"}} {
				b, _ := json.Marshal(map[string]any{"site": s.Root, "tool": "wp", "args": sub, "timeout_s": 180})
				if res, err := siteCLI(b); err == nil {
					r := res.(map[string]any)
					if r["exit_code"].(int) != 0 {
						add(finding{"high", "WordPress files differ from the official ones (wp " + strings.Join(sub, " ") + ")", s.Root, truncate(r["stderr"].(string)+r["stdout"].(string), 1500)})
					}
				}
			}
		}
	}

	// The hub's rules: known skimmers and backdoors, missing security patches, vulnerable modules.
	var ruled any
	if a.RulesFile != "" {
		rules, skipped := loadRules(a.RulesFile)
		rep := ruleScan(s, rules, add)
		rep.Skipped = append(rep.Skipped, skipped...)
		ruled = rep
	}

	counts := map[string]int{}
	for _, f := range found {
		counts[f.Severity]++
	}
	sort.SliceStable(found, func(i, j int) bool { return sevRank(found[i].Severity) < sevRank(found[j].Severity) })
	return map[string]any{"site": s.Root, "kind": s.Kind, "files_scanned": scanned, "seconds": int(time.Since(start).Seconds()), "counts": counts, "findings": found, "rule_checks": ruled,
		"note": "Pattern checks find common malware, not all of it. A finding is a lead to read, not proof; a clean result is not a guarantee."}, nil
}

func sevRank(s string) int { return map[string]int{"high": 0, "medium": 1, "low": 2}[s] }

func readHead(p string, n int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return string(b)
}

func snippet(text string, loc []int) string {
	from, to := max(loc[0]-60, 0), min(loc[1]+60, len(text))
	if to-from > 300 {
		to = from + 300
	}
	return strings.ToValidUTF8(strings.ReplaceAll(text[from:to], "\n", " "), "?")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "") + "…"
	}
	return s
}
