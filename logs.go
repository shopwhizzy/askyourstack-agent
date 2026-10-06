package main

// The logs tool: the logs people actually need, by name, for a time window,
// with repeated messages counted once. Reading "the last 200 lines" of a busy
// log shows one error two hundred times; this shows the twenty different
// errors, how often each happened and when, plus the latest lines.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const logTail = 8 << 20

var logKinds = map[string][]string{
	"web-error": {"/var/log/nginx/*error*.log", "/var/log/nginx/*/*error*.log", "/var/log/httpd/*error_log", "/var/log/httpd/*error*.log", "/var/log/apache2/*error*.log", "/usr/local/lsws/logs/error.log"},
	"php":       append([]string{"/var/log/php*.log", "/var/log/php/*.log"}, fpmLogs...),
	"database":  {"/var/log/mysql/error.log", "/var/log/mysql/*.err", "/var/log/mariadb/*.log", "/var/log/mysqld.log", "/var/lib/mysql/*.err"},
	"mail":      {"/var/log/maillog", "/var/log/mail.log"},
	"auth":      {"/var/log/secure", "/var/log/auth.log"},
}

// What journalctl is asked when a kind has no file on this server (or is "system").
var logJournal = map[string][]string{
	"system":   {"-p", "warning"},
	"mail":     {"-u", "postfix", "-u", "exim4", "-u", "exim", "-u", "sendmail"},
	"auth":     {"-u", "sshd", "-u", "ssh"},
	"database": {"-u", "mariadb", "-u", "mysqld", "-u", "mysql"},
}

// Routine lines that are not problems: left out unless the caller asks for them with match.
var logRoutine = map[string]*regexp.Regexp{
	"web-error": regexp.MustCompile(`^\[(notice|info|debug)\]`),
	"database":  regexp.MustCompile(`\[(Note|System)\]`),
	"php":       regexp.MustCompile(`^(NOTICE|DEBUG): `),
	"auth":      regexp.MustCompile(`session (opened|closed) for user|New session \d+ of user|Session \d+ logged out|Removed session`),
}

var logNames = "web-error, php, site, magento, wordpress, database, system, mail, auth"

// Timestamps at the start of a line, one per log family.
var logStamps = []struct {
	re     *regexp.Regexp
	layout string
}{
	{regexp.MustCompile(`^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?\]?`), "iso"}, // Magento, MySQL, journal, ISO
	{regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`), "2006/01/02 15:04:05"},                           // nginx error
	{regexp.MustCompile(`^\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})(?: [A-Za-z/_+-]+)?\]`), "02-Jan-2006 15:04:05"},   // PHP, PHP-FPM
	{regexp.MustCompile(`^\[\w{3} (\w{3} \d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]`), "apache"},                  // Apache error
	{regexp.MustCompile(`^(\w{3} [ \d]\d \d{2}:\d{2}:\d{2}) `), "syslog"},                                           // syslog
}

// logTime reads the time a line starts with and returns the rest of the line.
func logTime(line string, now time.Time) (time.Time, string, bool) {
	for _, s := range logStamps {
		m := s.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(line[len(m[0]):])
		var t time.Time
		var err error
		switch s.layout {
		case "iso":
			v := strings.Replace(m[1], " ", "T", 1)
			if m[2] != "" {
				zone := m[2]
				if len(zone) == 5 { // +0000
					zone = zone[:3] + ":" + zone[3:]
				}
				t, err = time.Parse(time.RFC3339, v+zone)
			} else {
				t, err = time.ParseInLocation("2006-01-02T15:04:05", v, time.Local)
			}
		case "apache":
			t, err = time.ParseInLocation("Jan 02 15:04:05 2006", m[1]+" "+m[2], time.Local)
		case "syslog":
			t, err = time.ParseInLocation("Jan _2 15:04:05 2006", m[1]+" "+fmt.Sprint(now.Year()), time.Local)
			if err == nil && t.After(now.Add(24*time.Hour)) {
				t = t.AddDate(-1, 0, 0) // a December line read in January
			}
		default:
			t, err = time.ParseInLocation(s.layout, m[1], time.Local)
		}
		if err == nil {
			return t, rest, true
		}
	}
	return time.Time{}, line, false
}

var (
	logIP      = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){3,7}\b`)
	logHex     = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	logNum     = regexp.MustCompile(`\d+`)
	logContext = regexp.MustCompile(`, client: .*$| \{".*$| \[\] \[\]$|, referer: .*$`)
	logPrefix  = regexp.MustCompile(`^\S+ ([\w@.\-/]+?)(?:\[\d+\])?: `) // journal and syslog: "host unit[pid]: "
	logPid     = regexp.MustCompile(`^\[(\w+)\] \d+#\d+: (?:\*\d+ )?|^\[\w+ \d+:\w+ \d+\] `)
)

// logShape is a message with what varies taken out, so the same error counts as one.
func logShape(msg string) string {
	msg = logPrefix.ReplaceAllString(msg, "$1: ")
	msg = logPid.ReplaceAllString(msg, "[$1] ")
	msg = logContext.ReplaceAllString(msg, "")
	msg = logIP.ReplaceAllString(msg, "IP")
	msg = logHex.ReplaceAllString(msg, "H")
	msg = logNum.ReplaceAllString(msg, "N")
	if len(msg) > 180 {
		msg = msg[:180]
	}
	return msg
}

type logEntry struct {
	at   time.Time
	text string // the first line and up to four that follow it (a stack trace's top)
	file string
}

// logEntries turns lines into entries: a line with a time starts one, lines without belong to the one before.
func logEntries(lines []string, file string, from, now time.Time) (in []logEntry, timed bool) {
	var cur *logEntry
	extra := 0
	flush := func() {
		if cur != nil && (cur.at.IsZero() || !cur.at.Before(from)) {
			in = append(in, *cur)
		}
		cur = nil
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if t, rest, ok := logTime(l, now); ok {
			flush()
			timed = true
			cur, extra = &logEntry{at: t, text: rest, file: file}, 0
		} else if cur != nil && timed {
			if extra < 4 {
				cur.text += "\n" + truncate(strings.TrimRight(l, " \t"), 300)
				extra++
			}
		} else {
			flush()
			cur = &logEntry{text: l, file: file}
		}
	}
	flush()
	return in, timed
}

func logFiles(kind string, s *site) ([]string, error) {
	var globs []string
	switch kind {
	case "magento", "wordpress", "site":
		// The site's own log, whatever kind of site it is (kinds.go).
		if s == nil {
			return nil, errors.New("say which site (see list_sites)")
		}
		if kind != "site" && s.Kind != kind {
			return nil, fmt.Errorf("%s is a %s site; ask for its log with log \"site\"", s.Root, s.Kind)
		}
		if globs = kindLogs(s); len(globs) == 0 {
			if len(kindOf(s.Kind).Logs) == 0 {
				return nil, fmt.Errorf("%s keeps no log file of its own; read web-error or php", kindOf(s.Kind).Label)
			}
			return nil, fmt.Errorf("%s has not written a log yet", s.Root)
		}
	default:
		g, ok := logKinds[kind]
		if !ok && logJournal[kind] == nil {
			return nil, fmt.Errorf("no log called %q; choose one of: %s, or give path", kind, logNames)
		}
		globs = append(globs, g...)
		all := vhosts()
		switch kind {
		case "web-error":
			var own []string
			for _, v := range all {
				if s == nil || servesSite(v, s) {
					own = append(own, v.ErrLogs...)
				}
			}
			if s != nil && len(own) > 0 {
				globs = own // the site has error logs of its own: the shared ones are other sites' noise
			} else {
				globs = append(globs, own...)
			}
		case "php":
			// Shared hosting writes PHP errors next to the code.
			sites := locateSites()
			if s != nil {
				sites = []*site{s}
			}
			for _, x := range sites {
				globs = append(globs, x.Root+"/error_log", x.Root+"/php_errors.log", x.Root+"/pub/error_log", x.Root+"/wp-admin/error_log")
			}
		}
	}
	var files []string
	seen := map[string]bool{}
	for _, g := range globs {
		m, _ := filepath.Glob(g)
		for _, f := range m {
			if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() && !seen[realPath(f)] {
				seen[realPath(f)] = true
				files = append(files, f)
			}
		}
	}
	return files, nil
}

func servesSite(v vhost, s *site) bool {
	root := realPath(s.Root)
	for _, r := range v.Roots {
		if r = realPath(r); r == root || filepath.Dir(r) == root {
			return true
		}
	}
	return false
}

func readLogs(raw json.RawMessage) (any, error) {
	var a struct {
		Log   string  `json:"log"`
		Path  string  `json:"path"`
		Site  string  `json:"site"`
		Hours float64 `json:"hours"`
		Match string  `json:"match"`
	}
	json.Unmarshal(raw, &a)
	if a.Hours <= 0 {
		a.Hours = 24
	}
	if a.Hours > 168 {
		a.Hours = 168
	}
	now := time.Now()
	from := now.Add(-time.Duration(a.Hours * float64(time.Hour)))

	var s *site
	if a.Site != "" || a.Log == "magento" || a.Log == "wordpress" || a.Log == "site" {
		var err error
		if s, err = pickSite(a.Site); err != nil {
			return nil, err
		}
	}
	var files []string
	kind := a.Log
	if a.Path != "" {
		if !filepath.IsAbs(a.Path) {
			return nil, errors.New("path must be absolute")
		}
		files, kind = []string{filepath.Clean(a.Path)}, a.Path
	} else {
		if kind == "" {
			return nil, fmt.Errorf("say which log: %s, or give path", logNames)
		}
		var err error
		if files, err = logFiles(kind, s); err != nil {
			return nil, err
		}
	}

	var entries []logEntry
	var read []map[string]any
	for _, f := range files {
		lines, cut, err := tailLines(f, logTail)
		if err != nil {
			read = append(read, map[string]any{"file": f, "error": err.Error()})
			continue
		}
		in, timed := logEntries(lines, f, from, now)
		info := map[string]any{"file": f, "entries": len(in)}
		if cut {
			info["note"] = "only the last 8 MB was read"
		}
		if !timed && len(in) > 400 {
			in = in[len(in)-400:] // no times in it: the window cannot be applied, so the end of the file
			info["entries"], info["note"] = len(in), "the lines carry no time: these are the last ones, whatever their age"
		}
		read = append(read, info)
		entries = append(entries, in...)
	}
	// Nothing on disk for this kind: the journal has it (or it is the system log).
	if a.Path == "" && len(files) == 0 || kind == "system" {
		if j := logJournal[kind]; j != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			args := append([]string{"--since", fmt.Sprintf("-%dmin", int(a.Hours*60)), "--no-pager", "-o", "short-iso", "-n", "20000"}, j...)
			out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
			if err != nil && len(out) == 0 {
				read = append(read, map[string]any{"file": "journal", "error": "journalctl gave nothing: " + err.Error()})
			} else {
				in, _ := logEntries(strings.Split(string(out), "\n"), "journal", from, now)
				read = append(read, map[string]any{"file": "journal", "entries": len(in)})
				entries = append(entries, in...)
			}
		}
	}
	if len(read) == 0 {
		return nil, fmt.Errorf("no %s log found on this server; pass path with the file to read", kind)
	}

	routine := 0
	if re := logRoutine[kind]; re != nil && a.Match == "" {
		kept := entries[:0]
		for _, e := range entries {
			if re.MatchString(e.text) {
				routine++
			} else {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	if a.Match != "" {
		want := strings.ToLower(a.Match)
		kept := entries[:0]
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.text), want) {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })

	type group struct {
		Count  int    `json:"count"`
		First  string `json:"first,omitempty"`
		Last   string `json:"last,omitempty"`
		Sample string `json:"sample"`
		File   string `json:"file,omitempty"`
		last   time.Time
	}
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
	}
	groups := map[string]*group{}
	for _, e := range entries {
		first, _, _ := strings.Cut(e.text, "\n")
		k := logShape(first)
		g := groups[k]
		if g == nil {
			g = &group{First: stamp(e.at), File: e.file}
			groups[k] = g
		}
		g.Count++
		g.Last, g.last, g.Sample = stamp(e.at), e.at, truncate(e.text, 700) // the newest occurrence is the sample
	}
	list := make([]*group, 0, len(groups))
	for _, g := range groups {
		if len(files) <= 1 {
			g.File = ""
		}
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].last.After(list[j].last)
	})
	different := len(list)
	if len(list) > 30 {
		list = list[:30]
	}
	var latest []map[string]string
	for _, e := range entries[max(0, len(entries)-10):] {
		latest = append(latest, map[string]string{"at": stamp(e.at), "text": truncate(e.text, 400)})
	}
	out := map[string]any{"log": kind, "hours": a.Hours, "read": read, "entries": len(entries), "different_messages": different, "groups": list, "latest": latest}
	if a.Match != "" {
		out["match"] = a.Match
	}
	if routine > 0 {
		out["routine_lines_left_out"] = routine
	}
	if kind == "magento" && s != nil {
		// Each error page a visitor saw left a file in var/report.
		n := 0
		reports, _ := filepath.Glob(s.Root + "/var/report/*")
		for _, r := range reports {
			if fi, err := os.Stat(r); err == nil && fi.ModTime().After(from) {
				n++
			}
		}
		out["error_pages_shown"] = fmt.Sprintf("%d new files in var/report in this window (each is an error page a visitor saw; read one with read_file)", n)
	}
	if len(entries) == 0 {
		out["note"] = "Nothing in this window. A quiet log is good news; try more hours or another log if you expected something."
	}
	return out, nil
}
