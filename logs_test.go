package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLogTime(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	for line, want := range map[string]string{
		`2026/10/05 11:58:01 [error] 812#812: *99 FastCGI sent in stderr`:                   "2026-10-05 11:58:01|[error] 812#812: *99 FastCGI sent in stderr",
		`[2026-10-05T11:58:01.123456+00:00] main.CRITICAL: Boom {"exception":"x"} []`:       "utc 2026-10-05 11:58:01|main.CRITICAL: Boom {\"exception\":\"x\"} []",
		`[05-Oct-2026 11:58:01 UTC] PHP Fatal error:  Uncaught Error in /var/www/a.php:12`:  "2026-10-05 11:58:01|PHP Fatal error:  Uncaught Error in /var/www/a.php:12",
		`[05-Oct-2026 11:58:01] WARNING: [pool www] child 12 exited`:                        "2026-10-05 11:58:01|WARNING: [pool www] child 12 exited",
		`[Mon Oct 05 11:58:01.123456 2026] [php:error] [pid 12:tid 3] [client 1.2.3.4:5] x`: "2026-10-05 11:58:01|[php:error] [pid 12:tid 3] [client 1.2.3.4:5] x",
		`Oct  5 11:58:01 web postfix/smtp[812]: ABC: status=deferred`:                       "2026-10-05 11:58:01|web postfix/smtp[812]: ABC: status=deferred",
		`2026-10-05T11:58:01+0000 web sshd[9]: Failed password for root`:                    "utc 2026-10-05 11:58:01|web sshd[9]: Failed password for root",
		`2026-10-05 11:58:01 0 [ERROR] InnoDB: something`:                                   "2026-10-05 11:58:01|0 [ERROR] InnoDB: something",
	} {
		at, rest, ok := logTime(line, now)
		got := at.Format("2006-01-02 15:04:05") + "|" + rest
		if strings.HasPrefix(want, "utc ") {
			got = "utc " + at.UTC().Format("2006-01-02 15:04:05") + "|" + rest
		}
		if !ok || got != want {
			t.Errorf("%s\n got %s\nwant %s", line, got, want)
		}
	}
	if _, _, ok := logTime("#0 /var/www/a.php(12): boom()", now); ok {
		t.Error("a stack trace line is not a new entry")
	}
	// A syslog line from December read in January belongs to last year.
	if at, _, _ := logTime("Dec 31 23:59:00 web cron[1]: x", time.Date(2027, 1, 1, 0, 5, 0, 0, time.Local)); at.Year() != 2026 {
		t.Errorf("year: %v", at)
	}
}

func TestLogShape(t *testing.T) {
	same := [][2]string{
		{`[error] 812#812: *99 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 1.2.3.4, server: shop.example, request: "GET /a?b=1 HTTP/2.0"`, `[error] 9#9: *12345 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 9.9.9.9, server: shop.example, request: "POST /checkout HTTP/2.0"`},
		{`main.CRITICAL: Product 1234 not found {"exception":"[object] (Magento..."} []`, `main.CRITICAL: Product 99 not found {"exception":"[object] (Other..."} []`},
		{`web sshd[812]: Failed password for root from 1.2.3.4 port 5555 ssh2`, `web sshd[99]: Failed password for root from 2001:db8::1 port 4000 ssh2`},
		{`PHP Warning:  Undefined array key "x" in /var/www/a.php on line 12`, `PHP Warning:  Undefined array key "x" in /var/www/a.php on line 12`},
	}
	for _, p := range same {
		if logShape(p[0]) != logShape(p[1]) {
			t.Errorf("should count as one:\n %s\n %s", logShape(p[0]), logShape(p[1]))
		}
	}
	if logShape(`PHP Warning:  Undefined array key "x" in /var/www/a.php on line 12`) == logShape(`PHP Warning:  Undefined array key "y" in /var/www/b.php on line 12`) {
		t.Error("different files are different errors")
	}
}

func TestReadLogs(t *testing.T) {
	d := t.TempDir()
	now := time.Now()
	at := func(ago time.Duration) string { return "[" + now.Add(-ago).Format("02-Jan-2006 15:04:05") + "]" }
	var b strings.Builder
	fmt.Fprintf(&b, "%s PHP Warning:  old one in /var/www/a.php on line 1\n", at(50*time.Hour))
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "%s PHP Warning:  Undefined variable $x in /var/www/a.php on line %d\n", at(time.Duration(60-i)*time.Minute), 7)
	}
	fmt.Fprintf(&b, "%s PHP Fatal error:  Uncaught Exception: no stock for 812 in /var/www/b.php:30\nStack trace:\n#0 /var/www/c.php(12): reserve()\n#1 {main}\n  thrown in /var/www/b.php on line 30\n", at(5*time.Minute))
	fmt.Fprintf(&b, "%s PHP Fatal error:  Uncaught Exception: no stock for 99 in /var/www/b.php:30\nStack trace:\n#0 /var/www/c.php(12): reserve()\n", at(2*time.Minute))
	put(t, d+"/php.log", b.String())

	raw, _ := json.Marshal(map[string]any{"path": d + "/php.log", "hours": 24})
	res, err := readLogs(raw)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(res)
	var out struct {
		Entries   int `json:"entries"`
		Different int `json:"different_messages"`
		Groups    []struct {
			Count  int
			Sample string
			First  string
			Last   string
		}
		Latest []struct{ Text string }
	}
	json.Unmarshal(j, &out)
	if out.Entries != 42 || out.Different != 2 || len(out.Groups) != 2 || out.Groups[0].Count != 40 || out.Groups[1].Count != 2 {
		t.Fatalf("got %s", j)
	}
	if !strings.Contains(out.Groups[1].Sample, "no stock for 99") || !strings.Contains(out.Groups[1].Sample, "#0 /var/www/c.php(12): reserve()") || out.Groups[0].First == out.Groups[0].Last {
		t.Errorf("sample or times: %+v", out.Groups)
	}
	if len(out.Latest) != 10 || !strings.Contains(out.Latest[9].Text, "no stock for 99") {
		t.Errorf("latest: %+v", out.Latest)
	}
	raw, _ = json.Marshal(map[string]any{"path": d + "/php.log", "match": "FATAL"})
	res, _ = readLogs(raw)
	if res.(map[string]any)["entries"] != 2 {
		t.Errorf("match: %v", res.(map[string]any)["entries"])
	}
	// Routine lines of a named log are left out, unless asked for.
	old := logKinds["database"]
	logKinds["database"] = []string{d + "/db.log"}
	defer func() { logKinds["database"] = old }()
	stamp := now.Add(-time.Minute).Format("2006-01-02 15:04:05")
	put(t, d+"/db.log", stamp+" 0 [Note] InnoDB: Buffer pool(s) load completed\n"+stamp+" 0 [Note] Server socket created\n"+stamp+" 12 [ERROR] InnoDB: Table shop/orders is corrupted\n")
	res, _ = readLogs([]byte(`{"log":"database"}`))
	if m := res.(map[string]any); m["entries"] != 1 || m["routine_lines_left_out"] != 2 {
		t.Errorf("routine lines: %v %v", m["entries"], m["routine_lines_left_out"])
	}
	res, _ = readLogs([]byte(`{"log":"database","match":"socket"}`))
	if res.(map[string]any)["entries"] != 1 {
		t.Errorf("match should see routine lines: %v", res.(map[string]any)["entries"])
	}
	if _, err := readLogs([]byte(`{"log":"nonsense"}`)); err == nil || !strings.Contains(err.Error(), "web-error") {
		t.Errorf("unknown log: %v", err)
	}
	if _, err := readLogs([]byte(`{"path":"relative.log"}`)); err == nil {
		t.Error("a relative path was accepted")
	}
}
