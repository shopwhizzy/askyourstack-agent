package main

// Server to server copies for migrations. The hub sets up a one-off link:
//   1. xfer_key on the target makes a throwaway SSH key.
//   2. xfer_allow on the source accepts that key for root, only from the
//      target's addresses, until it expires, and only to run
//      `sudowhizzy-agent xfer-serve <id>`, which allows nothing but a
//      read-only rsync inside the folder chosen for this link.
//   3. xfer_pull on the target runs rsync over SSH as a background job,
//      checking the source's host key that its own agent reported.
//   4. xfer_close on both removes the key.
// The data goes straight between the two servers, never through the hub.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var xferDir = stateDir("xfer")

var xferIDRe = regexp.MustCompile(`^[a-z0-9-]{8,64}$`)

type xferMeta struct {
	Root    string `json:"root"`
	Expires int64  `json:"expires"`
}

// Addresses other servers can reach this one on (global unicast only).
func publicIPs() []string {
	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || !n.IP.IsGlobalUnicast() || n.IP.IsPrivate() {
			continue
		}
		ips = append(ips, n.IP.String())
	}
	return ips
}

func xferKey(raw json.RawMessage) (any, error) {
	var a struct{ ID string }
	if json.Unmarshal(raw, &a) != nil || !xferIDRe.MatchString(a.ID) {
		return nil, errors.New("bad transfer id")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return nil, errors.New("the ssh client is missing on this server (dnf/apt install openssh-clients or openssh-client)")
	}
	dir := filepath.Join(xferDir, a.ID)
	key := filepath.Join(dir, "key")
	if _, err := os.Stat(key); err != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sudowhizzy-xfer-"+a.ID, "-f", key).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
		}
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		return nil, err
	}
	_, rsyncErr := exec.LookPath("rsync")
	return map[string]any{"public_key": strings.TrimSpace(string(pub)), "ips": publicIPs(), "rsync": rsyncErr == nil}, nil
}

var sshPubRe = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+( \S+)?$`)

func xferAllow(raw json.RawMessage) (any, error) {
	var a struct {
		ID        string   `json:"id"`
		PublicKey string   `json:"public_key"`
		From      []string `json:"from"`
		Root      string   `json:"root"`
		Expires   int64    `json:"expires"`
	}
	if json.Unmarshal(raw, &a) != nil || !xferIDRe.MatchString(a.ID) || !sshPubRe.MatchString(a.PublicKey) || len(a.From) == 0 {
		return nil, errors.New("bad transfer request")
	}
	for _, ip := range a.From {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("bad address %q", ip)
		}
	}
	root := filepath.Clean(a.Root)
	if !filepath.IsAbs(root) || root == "/" {
		return nil, errors.New("the folder to copy must be an absolute path below /")
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder on this server", root)
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return nil, errors.New("rsync is missing on this server; install it first (dnf/apt install rsync)")
	}
	// What sshd will actually do: port, whether root may use a key, host keys.
	cfg := map[string]string{}
	if out, err := exec.Command("sshd", "-T").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(l, " "); ok {
				if _, seen := cfg[k]; !seen {
					cfg[k] = v
				}
			}
		}
	}
	if cfg["permitrootlogin"] == "no" {
		return nil, errors.New("sshd on this server has PermitRootLogin no, so the copy cannot log in; allow prohibit-password (keys only) or copy another way")
	}
	port := cfg["port"]
	if port == "" {
		port = "22"
	}
	var hostKeys []string
	for _, f := range []string{"/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_rsa_key.pub"} {
		if b, err := os.ReadFile(f); err == nil {
			fields := strings.Fields(string(b))
			if len(fields) >= 2 {
				hostKeys = append(hostKeys, fields[0]+" "+fields[1])
			}
		}
	}
	if len(hostKeys) == 0 {
		return nil, errors.New("no SSH host keys found in /etc/ssh")
	}

	os.MkdirAll(xferDir, 0o700)
	meta, _ := json.Marshal(xferMeta{Root: root, Expires: a.Expires})
	if err := os.WriteFile(filepath.Join(xferDir, a.ID+".json"), meta, 0o600); err != nil {
		return nil, err
	}
	self, _ := os.Executable()
	if self == "" {
		self = "/usr/local/bin/" + agentName
	}
	fields := strings.Fields(a.PublicKey)
	line := fmt.Sprintf(`from="%s",expiry-time="%s",restrict,command="%s xfer-serve %s" %s %s sudowhizzy-xfer-%s`,
		strings.Join(a.From, ","), time.Unix(a.Expires, 0).UTC().Format("200601021504")+"Z", self, a.ID, fields[0], fields[1], a.ID)
	if err := setAuthorizedKey(a.ID, line); err != nil {
		return nil, err
	}
	return map[string]any{"port": port, "host_keys": hostKeys, "ips": publicIPs(), "root": root}, nil
}

const rootKeys = "/root/.ssh/authorized_keys"

// Replaces this link's line in root's authorized_keys (line == "" removes it),
// leaving every other line exactly as it was.
func setAuthorizedKey(id, line string) error {
	os.MkdirAll("/root/.ssh", 0o700)
	var keep []string
	removed := false
	if f, err := os.Open(rootKeys); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if strings.HasSuffix(strings.TrimSpace(sc.Text()), " sudowhizzy-xfer-"+id) {
				removed = true
			} else {
				keep = append(keep, sc.Text())
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	if line == "" && !removed {
		return nil
	}
	if line != "" {
		keep = append(keep, line)
	}
	body := strings.Join(keep, "\n")
	if body != "" {
		body += "\n"
	}
	tmp := rootKeys + ".sw-tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, rootKeys); err != nil {
		return err
	}
	// SELinux: a file made by us must carry the ssh_home_t label sshd expects.
	if _, err := exec.LookPath("restorecon"); err == nil {
		exec.Command("restorecon", "-F", "/root/.ssh", rootKeys).Run()
	}
	return nil
}

// sshd runs this (the forced command) for every login with a link's key. It
// allows only `rsync --server --sender ...` reading inside the link's folder.
func xferServe(id string) {
	fail := func(msg string) {
		fmt.Fprintln(os.Stderr, "sudowhizzy: "+msg)
		os.Exit(1)
	}
	if !xferIDRe.MatchString(id) {
		fail("bad link")
	}
	b, err := os.ReadFile(filepath.Join(xferDir, id+".json"))
	if err != nil {
		fail("this copy link is closed")
	}
	var m xferMeta
	if json.Unmarshal(b, &m) != nil || time.Now().Unix() > m.Expires {
		fail("this copy link has expired")
	}
	args := splitRsyncArgs(os.Getenv("SSH_ORIGINAL_COMMAND"))
	if err := checkRsyncSender(args, m.Root); err != nil {
		fail(err.Error())
	}
	bin, err := exec.LookPath("rsync")
	if err != nil {
		fail("rsync is missing")
	}
	syscall.Exec(bin, args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
	fail("could not start rsync")
}

// rsync escapes spaces and specials in the remote command with backslashes.
func splitRsyncArgs(s string) []string {
	var args []string
	var cur strings.Builder
	esc, have := false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc, have = false, true
		case r == '\\':
			esc = true
		case r == ' ' || r == '\t':
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

// Options that would make the sending side write, delete or read outside the folder.
var rsyncForbidden = regexp.MustCompile(`^--(remove|log-file|write-batch|only-write-batch|read-batch|files-from|include-from|exclude-from|temp-dir|backup|partial-dir|compare-dest|copy-dest|link-dest|rsync-path|config|daemon|password-file|copy-unsafe-links|copy-links|copy-dirlinks|keep-dirlinks|write-devices|sockopts|out-format|early-input)`)

func checkRsyncSender(args []string, root string) error {
	if len(args) < 4 || filepath.Base(args[0]) != "rsync" || args[1] != "--server" || args[2] != "--sender" {
		return errors.New("only a read-only rsync copy is allowed on this link")
	}
	paths := 0
	dot := false
	for _, a := range args[3:] {
		switch {
		case a == ".":
			dot = true
		case !dot && strings.HasPrefix(a, "-"):
			// A short bundle like -logDtpre.iLsfxCIvu: letters before "e." are options, after it rsync's capability flags.
			short := ""
			if !strings.HasPrefix(a, "--") {
				short = a[1:]
				if i := strings.Index(short, "e."); i >= 0 {
					short = short[:i]
				}
			}
			if rsyncForbidden.MatchString(a) || strings.ContainsAny(short, "LkK") {
				return fmt.Errorf("rsync option %s is not allowed on this link", a)
			}
		case dot:
			// No shell runs these, but paths with shell characters have no place in a migration.
			if strings.ContainsAny(a, ";|&$`<>\n") {
				return fmt.Errorf("path %q has characters not allowed on this link", a)
			}
			p := filepath.Clean(a)
			if !filepath.IsAbs(p) {
				p = filepath.Join(root, p)
			}
			if p != root && !strings.HasPrefix(p, root+"/") {
				return fmt.Errorf("%s is outside %s", a, root)
			}
			paths++
		default:
			return fmt.Errorf("unexpected argument %s", a)
		}
	}
	if paths == 0 {
		return errors.New("no folder given")
	}
	return nil
}

var hostRe = regexp.MustCompile(`^[0-9A-Fa-f.:]+$`)

func xferPull(raw json.RawMessage) (any, error) {
	var a struct {
		ID       string   `json:"id"`
		Host     string   `json:"host"`
		Port     string   `json:"port"`
		HostKeys []string `json:"host_keys"`
		Source   string   `json:"source"`
		Dest     string   `json:"dest"`
		Mirror   bool     `json:"mirror"`
		Excludes []string `json:"excludes"`
	}
	if json.Unmarshal(raw, &a) != nil || !xferIDRe.MatchString(a.ID) || !hostRe.MatchString(a.Host) || !regexp.MustCompile(`^\d{1,5}$`).MatchString(a.Port) {
		return nil, errors.New("bad transfer request")
	}
	key := filepath.Join(xferDir, a.ID, "key")
	if _, err := os.Stat(key); err != nil {
		return nil, errors.New("this link has no key here; start the transfer again")
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return nil, errors.New("rsync is missing on this server; install it first (dnf/apt install rsync)")
	}
	src, dst := filepath.Clean(a.Source), filepath.Clean(a.Dest)
	if !filepath.IsAbs(src) || !filepath.IsAbs(dst) || dst == "/" {
		return nil, errors.New("source and destination must be absolute paths, and the destination cannot be /")
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	// Pin the source's host key, as its own agent reported it.
	hostName := a.Host
	if a.Port != "22" {
		hostName = "[" + a.Host + "]:" + a.Port
	}
	var kh strings.Builder
	for _, k := range a.HostKeys {
		if !regexp.MustCompile(`^[a-z0-9-]+ [A-Za-z0-9+/=]+$`).MatchString(k) {
			return nil, errors.New("bad host key")
		}
		kh.WriteString(hostName + " " + k + "\n")
	}
	known := filepath.Join(xferDir, a.ID, "known_hosts")
	if err := os.WriteFile(known, []byte(kh.String()), 0o600); err != nil {
		return nil, err
	}
	sshCmd := fmt.Sprintf("ssh -i %s -p %s -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o ConnectTimeout=20 -o ServerAliveInterval=30", key, a.Port, known)
	remote := a.Host
	if strings.Contains(remote, ":") {
		remote = "[" + remote + "]"
	}
	cmd := []string{"rsync", "-aH", "--numeric-ids", "--info=stats2,progress2", "--no-inc-recursive", "-e", shellQuote(sshCmd)}
	if a.Mirror {
		cmd = append(cmd, "--delete")
	}
	for _, x := range a.Excludes {
		cmd = append(cmd, "--exclude="+shellQuote(x))
	}
	cmd = append(cmd, shellQuote("root@"+remote+":"+strings.TrimRight(src, "/")+"/"), shellQuote(strings.TrimRight(dst, "/")+"/"))
	job, _ := json.Marshal(map[string]string{"command": strings.Join(cmd, " "), "name": "transfer " + a.ID})
	return jobStart(job)
}

func xferClose(raw json.RawMessage) (any, error) {
	var a struct{ ID string }
	if json.Unmarshal(raw, &a) != nil || !xferIDRe.MatchString(a.ID) {
		return nil, errors.New("bad transfer id")
	}
	err := setAuthorizedKey(a.ID, "")
	os.Remove(filepath.Join(xferDir, a.ID+".json"))
	os.RemoveAll(filepath.Join(xferDir, a.ID))
	if err != nil {
		return nil, err
	}
	return map[string]any{"closed": a.ID}, nil
}
