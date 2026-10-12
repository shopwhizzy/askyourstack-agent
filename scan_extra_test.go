package main

import "testing"

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
	m := agentInCron.FindStringSubmatch(line)
	if m == nil || m[1] != "/home/wp/.local/bin/askyourstack-agent" {
		t.Fatalf("got %v", m)
	}
	if isAgentBinary("/bin/sh") || isAgentBinary("/tmp/nothing/askyourstack-agent") {
		t.Fatal("not an agent binary")
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
