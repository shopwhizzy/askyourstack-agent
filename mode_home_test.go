package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDataHomeFollowsAYSHome(t *testing.T) {
	t.Setenv("AYS_HOME", "/srv/apps/x/shared/")
	if got := dataHomeDir(); got != "/srv/apps/x/shared" {
		t.Fatalf("AYS_HOME not used: %q", got)
	}
	t.Setenv("AYS_HOME", "relative/dir")
	if got := dataHomeDir(); strings.Contains(got, "relative") {
		t.Fatalf("a relative AYS_HOME must be ignored: %q", got)
	}
	t.Setenv("AYS_HOME", "")
	if got := dataHomeDir(); got != agentHome {
		t.Fatalf("without AYS_HOME and outside .local/bin the real home is used: %q vs %q", got, agentHome)
	}
}

func TestStateAndConfigFollowDataHome(t *testing.T) {
	oldPriv, oldData := privileged, dataHome
	defer func() { privileged, dataHome = oldPriv, oldData }()
	privileged = false
	dataHome = t.TempDir()
	if !strings.HasPrefix(confDir(), dataHome) || !strings.HasPrefix(stateBase(), dataHome) {
		t.Fatalf("config %q and state %q must sit under %q", confDir(), stateBase(), dataHome)
	}
	if filepath.Base(confFile()) != "agent.json" {
		t.Fatalf("unexpected config file %q", confFile())
	}
}

func TestProtectedPathCoversDataHome(t *testing.T) {
	oldPriv, oldData := privileged, dataHome
	defer func() { privileged, dataHome = oldPriv, oldData }()
	privileged = false
	dataHome = t.TempDir()
	if !protectedPath(filepath.Join(dataHome, ".config", "askyourstack", "agent.json")) {
		t.Fatal("the agent's config under its own folder must stay protected")
	}
}
