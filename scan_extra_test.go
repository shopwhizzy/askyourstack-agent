package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlyMissing(t *testing.T) {
	if !onlyMissing("Warning: File doesn't exist: wp-includes/a.php\nWarning: File doesn't exist: wp-includes/b.php\nError: WordPress installation doesn't verify against checksums.\n") {
		t.Fatal("missing files only should be onlyMissing")
	}
	if onlyMissing("Warning: File doesn't verify against checksum: wp-login.php\nError: WordPress installation doesn't verify against checksums.") {
		t.Fatal("a changed file is not only missing")
	}
	if onlyMissing("Warning: File should not exist: wp-content/x.php\n") {
		t.Fatal("an extra file is not only missing")
	}
	if onlyMissing("") {
		t.Fatal("empty is not only missing")
	}
}

func TestAgentInCron(t *testing.T) {
	line := "wp: * * * * * [ -e /home/wp/.config/askyourstack/stopped ]  flock -n /home/wp/.config/askyourstack/agent.lock /home/wp/.local/bin/askyourstack-agent >> /home/wp/.config/askyourstack/agent.log 2>&1 # askyourstack-agent"
	if !agentCronLine.MatchString("scheduled task: "+strings.ReplaceAll(line, "]  flock", "] || flock")) || !agentCronLine.MatchString("scheduled task: "+line) {
		t.Fatal("the watchdog line, with or without ||, is ours")
	}
	pid := "wp: * * * * * [ -e /h/.config/askyourstack/stopped ]  [ -e /h/.config/askyourstack/agent.pid ] && kill -0 $(cat /h/.config/askyourstack/agent.pid) 2>/dev/null  /h/.local/bin/askyourstack-agent >> /h/.config/askyourstack/agent.log 2>&1 # askyourstack-agent"
	if !agentCronLine.MatchString("x: " + pid) {
		t.Fatal("the pid-check watchdog line is ours")
	}
	for _, bad := range []string{
		strings.Replace(line, "* * * * * ", "* * * * * /tmp/evil; ", 1),
		strings.Replace(line, " # askyourstack-agent", "; /home/wp/.cache/x # askyourstack-agent", 1),
		"wp: * * * * * /home/wp/.cache/x # askyourstack-agent",
	} {
		if agentCronLine.MatchString("x: " + bad) {
			t.Fatalf("not ours: %s", bad)
		}
	}
	m := agentInCron.FindStringSubmatch(line)
	if m == nil || m[1] != "/home/wp/.local/bin/askyourstack-agent" {
		t.Fatalf("got %v", m)
	}
	if isAgentBinary("/bin/sh", knownAgents("")) || isAgentBinary("/tmp/nothing/askyourstack-agent", knownAgents("")) {
		t.Fatal("not an agent binary")
	}
}

func TestAgentBinaryByHash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "askyourstack-agent")
	os.WriteFile(p, []byte("not really an agent, but carries askyourstack/agent"), 0o755)
	h, _ := fileSHA256(p)
	if isAgentBinary(p, knownAgents("")) {
		t.Fatal("name and module text alone must not be trusted")
	}
	if !isAgentBinary(p, knownAgents("0000000000000000000000000000000000000000000000000000000000000000,"+h)) {
		t.Fatal("a listed release hash is an agent")
	}
	other := filepath.Join(dir, "htop")
	os.WriteFile(other, []byte("x"), 0o755)
	if h2, _ := fileSHA256(other); isAgentBinary(other, knownAgents(h2)) {
		t.Fatal("a listed hash under another name is not the agent")
	}
	if len(knownAgents("zz,ABC")) > 1 {
		t.Fatal("only lowercase hex hashes are taken")
	}
}

func TestJSONLogLine(t *testing.T) {
	at, text, ok := jsonLogLine(`{"name":"Log","hostname":"h","pid":42062,"level":50,"version":"6.69.0","msg":"Could not get webhook secret","err":{"message":"fetch failed"},"time":"2026-10-12T10:24:33.322Z","v":0}`)
	if !ok || text != "ERROR Could not get webhook secret: fetch failed" || at.Year() != 2026 {
		t.Fatalf("got %v %q %v", ok, text, at)
	}
	if _, _, ok := jsonLogLine(`[2026-10-12 10:00:00] not json`); ok {
		t.Fatal("plain line read as JSON")
	}
}

func TestDropVerifiedCore(t *testing.T) {
	in := func() []finding {
		return []finding{
			{"medium", "long hex-escaped string", "wp-includes/SimplePie/src/Misc.php:2028", ""},
			{"medium", "long hex-escaped string", "wp-includes/evil.php:3", ""},
			{"high", "PHP file in an upload folder", "wp-content/uploads/x.php", ""},
		}
	}
	got := dropVerifiedCore(in(), 0, "Warning: File should not exist: wp-includes/evil.php\nSuccess: WordPress installation verifies against checksums.")
	if len(got) != 2 || got[0].Where != "wp-includes/evil.php:3" || got[1].Where != "wp-content/uploads/x.php" {
		t.Fatalf("verified core: %+v", got)
	}
	if got := dropVerifiedCore(in(), 1, "Warning: File doesn't verify against checksum: wp-login.php\nError: WordPress installation doesn't verify against checksums."); len(got) != 3 {
		t.Fatalf("changed core keeps everything: %+v", got)
	}
}

func TestOnlyMissingColoured(t *testing.T) {
	if !onlyMissing("\x1b[36;1mWarning:\x1b[0m File doesn't exist: wp-includes/a.php\n\x1b[31;1mError:\x1b[0m WordPress installation doesn't verify against checksums.") {
		t.Fatal("coloured wp-cli output must read the same")
	}
}
