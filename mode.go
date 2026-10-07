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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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

// firstDir picks the new-name folder when it exists, else the old-name one when that
// exists (an install not yet moved by migrate), else the new name for a fresh install.
func firstDir(newPath, oldPath string) string {
	if _, err := os.Stat(newPath); err == nil {
		return newPath
	}
	if _, err := os.Stat(oldPath); err == nil {
		return oldPath
	}
	return newPath
}

// State lives under /var/lib/askyourstack for root, or in the user's home otherwise.
func stateBase() string {
	if privileged {
		return firstDir("/var/lib/askyourstack", "/var/lib/sudowhizzy")
	}
	return firstDir(filepath.Join(agentHome, ".local", "share", "askyourstack"), filepath.Join(agentHome, ".local", "share", "sudowhizzy"))
}

func stateDir(name string) string { return filepath.Join(stateBase(), name) }

func confDir() string {
	if privileged {
		return firstDir("/etc/askyourstack", "/etc/sudowhizzy")
	}
	return firstDir(filepath.Join(agentHome, ".config", "askyourstack"), filepath.Join(agentHome, ".config", "sudowhizzy"))
}

func confFile() string { return filepath.Join(confDir(), "agent.json") }

// resolvePath cleans p and follows symlinks, in the part of it that exists and in a
// dangling link, so two spellings of one file compare equal.
func resolvePath(p string) string {
	p = filepath.Clean(p)
	for i := 0; i < 40; i++ {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		// Not all of it exists. Find the deepest part that does: a dangling symlink is
		// followed by hand, anything else is resolved and the rest put back.
		cur := p
		for ; cur != "/" && cur != "."; cur = filepath.Dir(cur) {
			if _, err := os.Lstat(cur); err == nil {
				break
			}
		}
		rel, _ := filepath.Rel(cur, p)
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			dest, err := os.Readlink(cur)
			if err != nil {
				return p
			}
			if !filepath.IsAbs(dest) {
				dest = filepath.Join(filepath.Dir(cur), dest)
			}
			p = filepath.Clean(filepath.Join(dest, rel))
			continue
		}
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rel)
		}
		return p
	}
	return p
}

// protectedPath: the agent's own folder (key, lock, pid), its binary with the .prev
// and .new copies, and its service units. The hub refuses these by name; the agent
// refuses them by what they really are, so no spelling (/etc//x, /etc/./x, a/../x)
// or symlink reaches them through read_file, write_file or rollback.
func protectedPath(p string) bool {
	real := resolvePath(p)
	dirs := []string{"/etc/askyourstack", "/etc/sudowhizzy", confDir()}
	if agentHome != "" {
		dirs = append(dirs, filepath.Join(agentHome, ".config", "askyourstack"), filepath.Join(agentHome, ".config", "sudowhizzy"))
	}
	for _, d := range dirs {
		if d = resolvePath(d); real == d || strings.HasPrefix(real, d+"/") {
			return true
		}
	}
	base := filepath.Base(real)
	if strings.HasPrefix(base, "askyourstack-agent") || strings.HasPrefix(base, "sudowhizzy-agent") {
		return true
	}
	if self, err := os.Executable(); err == nil {
		self = resolvePath(self)
		if real == self || real == self+".prev" || real == self+".new" {
			return true
		}
	}
	return false
}

var errProtected = errors.New("that is the agent's own file (its key, lock, binary or service unit); it is never read or changed through AskYourStack")

// writeAtomic writes data to path through a randomly named file in the same folder
// and renames it into place. A fixed temporary name would let a local user plant a
// symlink there and have a root agent write somewhere else.
func writeAtomic(path string, data io.Reader, mode os.FileMode, uid, gid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".sw-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Chmod(tmp, mode)
	if uid >= 0 {
		os.Chown(tmp, uid, gid)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// layout says which install this is, for the hub: "askyourstack" after the rename, else "sudowhizzy".
func layout() string {
	if strings.Contains(confPath, "askyourstack") {
		return "askyourstack"
	}
	return "sudowhizzy"
}

// reloadPaths recomputes every path after migrate() moved the install.
func reloadPaths() {
	jobsDir, snapDir, backupDir, dumpDir = stateDir("jobs"), stateDir("snapshots"), stateDir("backups"), stateDir("dumps")
	confPath = confFile()
	pidFile = filepath.Join(filepath.Dir(confPath), "agent.pid")
	stopFile = filepath.Join(filepath.Dir(confPath), "stopped")
	lockFile = filepath.Join(filepath.Dir(confPath), "lock")
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
