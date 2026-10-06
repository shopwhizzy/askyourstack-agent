package main

// Two ways to run the agent on a customer box:
//   - privileged (root): a system service, manages the whole server.
//   - unprivileged: started by an ordinary, possibly jailed, Linux user
//     (shared hosting, an agency's per-client account). It manages that user's
//     own shop and files only. It cannot touch the system (packages, services,
//     /etc, SSL, other users), and says so clearly when asked.
// The mode is decided at startup from the effective uid, never configured.
// Each running agent is one connection to the hub (its own token), so a root
// agent and a user agent on the same machine count as two servers on the plan.

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

var (
	privileged = os.Geteuid() == 0
	agentHome  = homeDir()

	jobsDir   = stateDir("jobs")
	snapDir   = stateDir("snapshots")
	backupDir = stateDir("backups")
	dumpDir   = stateDir("dumps")
	confPath  = confFile()

	// Background jobs use transient systemd units only as root; an unprivileged
	// user usually cannot reach the system manager, so those jobs run detached.
	systemdJobs = privileged && have("systemd-run") && have("systemctl")
)

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/root"
}

// State lives under /var/lib/sudowhizzy for root, or in the user's home otherwise.
func stateDir(name string) string {
	if privileged {
		return filepath.Join("/var/lib/sudowhizzy", name)
	}
	return filepath.Join(agentHome, ".local", "share", "sudowhizzy", name)
}

func confFile() string {
	if privileged {
		return "/etc/sudowhizzy/agent.json"
	}
	return filepath.Join(agentHome, ".config", "sudowhizzy", "agent.json")
}

func agentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return fmt.Sprintf("uid-%d", os.Geteuid())
}

func have(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// When started by the user watchdog (no systemd), two files coordinate it:
// pidFile says the agent is running, stopFile says it was revoked so the
// watchdog must not restart it. Both sit next to the config. Harmless as root.
var (
	pidFile  = filepath.Join(filepath.Dir(confPath), "agent.pid")
	stopFile = filepath.Join(filepath.Dir(confPath), "stopped")
)

func writePid()     { os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o600) }
func markStopped()  { os.WriteFile(stopFile, []byte("revoked by the hub\n"), 0o600) }
func clearStopped() { os.Remove(stopFile) }

// homeEnv is the PATH and HOME a shell command runs with. An unprivileged user
// keeps their own home and adds their local bin dirs.
func homeEnv() []string {
	base := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if privileged {
		return []string{"HOME=/root", "PATH=" + base}
	}
	return []string{"HOME=" + agentHome, "PATH=" + filepath.Join(agentHome, ".local", "bin") + ":" + filepath.Join(agentHome, "bin") + ":" + base}
}
