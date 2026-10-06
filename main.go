// sudowhizzy-agent runs on a customer server as root. It asks the hub for
// jobs over HTTPS (long poll), runs them and posts the results back. It never
// listens on a port, so nothing on the server is opened to the internet.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	version = "0.13.0"
	// Releases are signed with the matching private key, kept on the control plane.
	releaseKey = "yipnfd7HAM5S31jEJZiYO2hTQJD1Z2QrxUCN1jQkYic="
	keepAuto   = 20
	// exitRevoked tells systemd not to restart us: the hub no longer knows this server.
	exitRevoked = 3
	// sourceRepo holds the public source; release.sh sets sourceCommit to the
	// commit the binary was built from (go build -ldflags "-X main.sourceCommit=...").
	sourceRepo = "https://github.com/shopwhizzy/sudowhizzy-agent"
)

var sourceCommit = "unreleased"

type config struct {
	Hub   string `json:"hub"`
	Token string `json:"token"`
}

type job struct {
	ID   string          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

var client = &http.Client{Timeout: 60 * time.Second}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "enroll" {
		if err := enroll(strings.TrimRight(os.Args[2], "/"), os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "enroll failed:", err)
			os.Exit(1)
		}
		fmt.Println("enrolled")
		return
	}
	// Run by malware_scan as a background job: prints the report as JSON.
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "scan" {
		rulesFile := ""
		if len(os.Args) == 5 {
			rulesFile = os.Args[4]
		}
		b, _ := json.Marshal(map[string]any{"site": os.Args[2], "days": atoiOr(os.Args[3], 14), "rules_file": rulesFile})
		out, err := malwareScanNow(b)
		if err != nil {
			fmt.Println(`{"error":` + strconvQuote(err.Error()) + `}`)
			os.Exit(1)
		}
		j, _ := json.MarshalIndent(out, "", " ")
		fmt.Println(string(j))
		return
	}
	// sshd's forced command for a migration copy link (transfer.go).
	if len(os.Args) == 3 && os.Args[1] == "xfer-serve" {
		xferServe(os.Args[2])
		return
	}
	// Run by site_audit as a background job (audit.go).
	if len(os.Args) == 3 && os.Args[1] == "siteaudit" {
		if err := siteAuditNow(os.Args[2]); err != nil {
			fmt.Println("audit failed:", err)
			os.Exit(1)
		}
		return
	}
	// Run by convert_images as a background job, as the site's owner.
	if len(os.Args) == 3 && os.Args[1] == "imgconvert" {
		if err := imagesRun(os.Args[2]); err != nil {
			fmt.Println("conversion failed:", err)
			os.Exit(1)
		}
		return
	}
	// Run by db_restore as a background job.
	if len(os.Args) == 4 && os.Args[1] == "dbrestore" {
		if err := dbRestoreNow(os.Args[2], os.Args[3]); err != nil {
			fmt.Println("restore failed:", err)
			os.Exit(1)
		}
		return
	}
	// Run by db_dump as a background job.
	if len(os.Args) == 4 && os.Args[1] == "dbdump" {
		if err := dbDumpNow(os.Args[2], os.Args[3]); err != nil {
			fmt.Println("dump failed:", err)
			os.Exit(1)
		}
		return
	}
	// For us, before putting a new hub/scan_rules.json live: which rules this agent cannot run.
	if len(os.Args) == 3 && os.Args[1] == "rules-check" {
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		var all []struct {
			ID      string `json:"id"`
			Enabled *bool  `json:"enabled"`
		}
		json.Unmarshal(b, &all)
		rules, skipped := parseRules(b)
		fmt.Printf("%d rules in the file, %d usable, cannot run: %v\n", len(all), len(rules), skipped)
		return
	}
	// For support: what list_sites would answer on this machine.
	if len(os.Args) == 2 && os.Args[1] == "sites" {
		out, _ := listSites()
		j, _ := json.MarshalIndent(out, "", " ")
		fmt.Println(string(j))
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	// What this binary was built from, for anyone checking it against the source.
	if len(os.Args) == 2 && os.Args[1] == "build" {
		fmt.Printf("version %s\nsource %s\ncommit %s\ngo %s\n", version, sourceRepo, sourceCommit, runtime.Version())
		return
	}
	// The administrator's own lock, see lock.go.
	if len(os.Args) == 2 && (os.Args[1] == "lock" || os.Args[1] == "unlock") {
		if err := setLock(os.Args[1] == "lock"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	raw, err := os.ReadFile(confPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no config, run: sudowhizzy-agent enroll <hub> <token>")
		os.Exit(1)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintln(os.Stderr, "bad config:", err)
		os.Exit(1)
	}
	writePid()
	loop(c)
}

func enroll(hub, token string) error {
	host, _ := os.Hostname()
	req := map[string]string{"token": token, "hostname": host, "version": version, "user": agentUser(), "privileged": fmt.Sprintf("%t", privileged)}
	// Installed here before: the hub disconnects that old identity, so one machine is one server.
	if raw, err := os.ReadFile(confPath); err == nil {
		var old config
		if json.Unmarshal(raw, &old) == nil && old.Hub == hub && old.Token != "" {
			req["previous"] = old.Token
		}
	}
	body, _ := json.Marshal(req)
	res, err := client.Post(hub+"/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 500))
		return fmt.Errorf("%s: %s", res.Status, msg)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.Token == "" {
		return errors.New("hub sent no token")
	}
	conf, _ := json.Marshal(config{Hub: hub, Token: out.Token})
	if err := os.MkdirAll(filepath.Dir(confPath), 0o700); err != nil {
		return err
	}
	clearStopped()
	return os.WriteFile(confPath, conf, 0o600)
}

func loop(c config) {
	for {
		req, _ := http.NewRequest("GET", c.Hub+"/agent/poll", nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("X-Agent-Version", version)
		if locked() {
			req.Header.Set("X-Agent-Locked", "1")
		}
		res, err := client.Do(req)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if latest := res.Header.Get("X-Agent-Latest"); latest != "" {
			maybeUpdate(c, latest)
		}
		switch res.StatusCode {
		case 200:
			var j job
			err := json.NewDecoder(res.Body).Decode(&j)
			res.Body.Close()
			if err == nil {
				active.Add(1)
				go func() { defer active.Add(-1); report(c, j.ID, handle(j)) }()
			}
		case 204:
			res.Body.Close()
		case 401, 403:
			res.Body.Close()
			fmt.Fprintln(os.Stderr, "the hub refused this agent's token; stopping")
			markStopped()
			os.Exit(exitRevoked)
		default:
			res.Body.Close()
			time.Sleep(5 * time.Second)
		}
	}
}

type result struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func handle(j job) (res result) {
	// A bug in one tool answers that call with an error; it must not take the agent down.
	defer func() {
		if p := recover(); p != nil {
			res = result{ID: j.ID, Error: fmt.Sprintf("the agent hit a bug running %s: %v", j.Op, p)}
		}
	}()
	var (
		out any
		err error
	)
	if why := lockRefuses(j.Op, j.Args); why != "" {
		return result{ID: j.ID, Error: why}
	}
	switch j.Op {
	case "facts":
		out = facts()
	case "run":
		out, err = run(j.Args)
	case "read_file":
		out, err = readFile(j.Args)
	case "write_file":
		out, err = writeFile(j.Args)
	case "snapshot":
		out, err = snapshot(j.Args)
	case "list_snapshots":
		out, err = listSnapshots()
	case "rollback":
		out, err = rollback(j.Args)
	case "job_start":
		out, err = jobStart(j.Args)
	case "job_output":
		out, err = jobOutput(j.Args)
	case "job_stop":
		out, err = jobStop(j.Args)
	case "jobs":
		out, err = jobList()
	case "sites":
		out, err = listSites()
	case "health":
		out, err = health(j.Args)
	case "traffic":
		out, err = traffic()
	case "logs":
		out, err = readLogs(j.Args)
	case "crawl":
		out, err = crawlReport(j.Args)
	case "db_query":
		out, err = dbQuery(j.Args)
	case "site_cli":
		out, err = siteCLI(j.Args)
	case "xfer_key":
		out, err = xferKey(j.Args)
	case "xfer_allow":
		out, err = xferAllow(j.Args)
	case "xfer_pull":
		out, err = xferPull(j.Args)
	case "xfer_close":
		out, err = xferClose(j.Args)
	case "db_dump":
		out, err = dbDumpStart(j.Args)
	case "table_dump":
		out, err = tableDump(j.Args)
	case "dumps":
		out, err = listDumps(j.Args)
	case "db_restore":
		out, err = dbRestoreStart(j.Args)
	case "images_convert":
		out, err = imagesStart(j.Args)
	case "audit_start":
		out, err = auditStart(j.Args)
	case "audit_query":
		out, err = auditQuery(j.Args)
	case "malware_scan":
		out, err = malwareScan(j.Args)
	default:
		err = fmt.Errorf("unknown op %q", j.Op)
	}
	if err != nil {
		return result{ID: j.ID, Error: err.Error()}
	}
	return result{ID: j.ID, OK: true, Result: out}
}

func report(c config, id string, r result) {
	body, _ := json.Marshal(r)
	for try := 0; try < 5; try++ {
		req, _ := http.NewRequest("POST", c.Hub+"/agent/result", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode < 500 {
				return
			}
		}
		time.Sleep(time.Duration(try+1) * 2 * time.Second)
	}
}

// --- facts

func facts() map[string]any {
	f := map[string]any{"agent_version": version, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "privileged": privileged, "user": agentUser(), "locked": locked()}
	f["hostname"], _ = os.Hostname()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f["kernel"] = strings.TrimSpace(string(b))
	}
	if osr := keyValues("/etc/os-release", "="); osr != nil {
		f["os"] = map[string]string{"id": osr["ID"], "id_like": osr["ID_LIKE"], "name": osr["PRETTY_NAME"], "version": osr["VERSION_ID"]}
	}
	if mi := keyValues("/proc/meminfo", ":"); mi != nil {
		f["memory"] = map[string]string{"total": mi["MemTotal"], "available": mi["MemAvailable"], "swap_total": mi["SwapTotal"]}
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		gb := func(n uint64) string { return fmt.Sprintf("%.1f GB", float64(n*uint64(st.Bsize))/1e9) }
		f["disk_root"] = map[string]string{"size": gb(st.Blocks), "free": gb(st.Bavail)}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f["load"] = strings.Join(strings.Fields(string(b))[:3], " ")
	}
	var pms []string
	for _, pm := range []string{"apt-get", "dnf", "yum", "apk", "zypper", "pacman"} {
		if _, err := exec.LookPath(pm); err == nil {
			pms = append(pms, pm)
		}
	}
	f["package_managers"] = pms
	if out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain").Output(); err == nil {
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			if fs := strings.Fields(l); len(fs) > 0 {
				names = append(names, strings.TrimSuffix(fs[0], ".service"))
			}
		}
		f["running_services"] = names
	}
	if out, err := exec.Command("ss", "-tlnHp").Output(); err == nil {
		f["listening_tcp"] = strings.TrimSpace(string(out))
	}
	sites := map[string][]string{}
	for _, s := range locateSites() {
		sites[s.Kind] = append(sites[s.Kind], s.Root)
	}
	f["sites_found"] = sites
	return f
}

func keyValues(path, sep string) map[string]string {
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), sep)
		if ok {
			m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return m
}

// --- run

// capped keeps the first and last part of a stream; logs and installers put
// the useful line at the end, so the tail matters more than the head.
type capped struct {
	head, tail []byte
	total      int
}

const headCap, tailCap = 16 << 10, 48 << 10

func (c *capped) Write(p []byte) (int, error) {
	n0 := len(p)
	c.total += n0
	if room := headCap - len(c.head); room > 0 {
		n := min(room, len(p))
		c.head = append(c.head, p[:n]...)
		p = p[n:]
	}
	c.tail = append(c.tail, p...)
	if len(c.tail) > tailCap {
		c.tail = c.tail[len(c.tail)-tailCap:]
	}
	return n0, nil
}

func (c *capped) String() string {
	kept := len(c.head) + len(c.tail)
	if kept >= c.total {
		return string(c.head) + string(c.tail)
	}
	return fmt.Sprintf("%s\n... [%d bytes cut] ...\n%s", c.head, c.total-kept, c.tail)
}

func run(raw json.RawMessage) (any, error) {
	var a struct {
		Command  string `json:"command"`
		Cwd      string `json:"cwd"`
		TimeoutS int    `json:"timeout_s"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || strings.TrimSpace(a.Command) == "" {
		return nil, errors.New("command is required")
	}
	if a.TimeoutS <= 0 {
		a.TimeoutS = 120
	}
	a.TimeoutS = min(a.TimeoutS, 1800)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.TimeoutS)*time.Second)
	defer cancel()
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-c", a.Command)
	cmd.Dir = a.Cwd
	cmd.Env = append(append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "TERM=dumb"), homeEnv()...)
	// Own process group, so a timeout kills the whole tree, not just the shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		return nil, err
	}
	return map[string]any{
		"exit_code": code, "timed_out": ctx.Err() != nil, "seconds": time.Since(start).Seconds(),
		"stdout": stdout.String(), "stderr": stderr.String(),
	}, nil
}

// --- files

const maxRead = 1 << 20

func readFile(raw json.RawMessage) (any, error) {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || !filepath.IsAbs(a.Path) {
		return nil, errors.New("path must be absolute")
	}
	fi, err := os.Stat(a.Path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, errors.New("that is a directory; use run with ls")
	}
	fh, err := os.Open(a.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxRead))
	if err != nil {
		return nil, err
	}
	out := map[string]any{"path": a.Path, "size": fi.Size(), "mode": fmt.Sprintf("%04o", fi.Mode().Perm()), "modified": fi.ModTime().UTC().Format(time.RFC3339), "truncated": fi.Size() > maxRead}
	if utf8.Valid(b) {
		out["content"] = string(b)
	} else {
		out["encoding"], out["content"] = "base64", base64.StdEncoding.EncodeToString(b)
	}
	return out, nil
}

func writeFile(raw json.RawMessage) (any, error) {
	var a struct {
		Path     string `json:"path"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Mode     string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || !filepath.IsAbs(a.Path) {
		return nil, errors.New("path must be absolute")
	}
	data := []byte(a.Content)
	if a.Encoding == "base64" {
		var err error
		if data, err = base64.StdEncoding.DecodeString(a.Content); err != nil {
			return nil, err
		}
	}
	mode := os.FileMode(0o644)
	uid, gid := -1, -1
	backup := ""
	if fi, err := os.Stat(a.Path); err == nil {
		if fi.IsDir() {
			return nil, errors.New("that is a directory")
		}
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
		// Keep the previous version so the change can be undone.
		backup = filepath.Join(backupDir, time.Now().UTC().Format("20060102T150405.000000000Z"), a.Path)
		old, err := os.ReadFile(a.Path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return nil, err
		}
	}
	if a.Mode != "" {
		var m uint32
		if _, err := fmt.Sscanf(a.Mode, "%o", &m); err != nil {
			return nil, errors.New("mode must be octal, like 0644")
		}
		mode = os.FileMode(m)
	}
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o755); err != nil {
		return nil, err
	}
	tmp := a.Path + ".sudowhizzy-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return nil, err
	}
	os.Chmod(tmp, mode)
	if uid >= 0 {
		os.Chown(tmp, uid, gid)
	}
	if err := os.Rename(tmp, a.Path); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return map[string]any{"path": a.Path, "bytes": len(data), "previous_version": backup}, nil
}

// --- snapshots
//
// A snapshot is a folder under snapDir holding files.tar.gz (absolute paths,
// owners, modes, times, symlinks), optional gzipped mysqldump files and
// meta.json. Rollback writes the archived files back; it does not delete
// files created after the snapshot.

type snapMeta struct {
	ID        string            `json:"id"`
	Label     string            `json:"label"`
	Paths     []string          `json:"paths"`
	Databases map[string]string `json:"databases,omitempty"` // name -> dump file or error
	Created   string            `json:"created"`
	Files     int               `json:"files"`
	Skipped   int               `json:"skipped"`
	Bytes     int64             `json:"bytes"`
}

var labelClean = regexp.MustCompile(`[^a-z0-9-]+`)

func snapshot(raw json.RawMessage) (any, error) {
	var a struct {
		Paths     []string `json:"paths"`
		Databases []string `json:"databases"`
		Label     string   `json:"label"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if len(a.Paths) == 0 && len(a.Databases) == 0 {
		return nil, errors.New("give paths and/or databases")
	}
	for _, p := range a.Paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) == "/" {
			return nil, fmt.Errorf("%q: paths must be absolute and not /", p)
		}
	}
	return takeSnapshot(a.Paths, a.Databases, a.Label)
}

func takeSnapshot(paths, databases []string, label string) (*snapMeta, error) {
	// Refuse when the copy could eat more than half of the free space.
	var need int64
	for _, p := range paths {
		filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil {
					need += fi.Size()
				}
			}
			return nil
		})
	}
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		return nil, err
	}
	var st syscall.Statfs_t
	if syscall.Statfs(snapDir, &st) == nil {
		if free := int64(st.Bavail) * int64(st.Bsize); need > free/2 {
			return nil, fmt.Errorf("the paths hold %.1f GB but only %.1f GB is free; snapshot fewer paths", float64(need)/1e9, float64(free)/1e9)
		}
	}
	label = strings.Trim(labelClean.ReplaceAllString(strings.ToLower(label), "-"), "-")
	if label == "" {
		label = "manual"
	}
	m := &snapMeta{ID: time.Now().UTC().Format("20060102T150405Z") + "-" + label, Label: label, Paths: paths, Created: time.Now().UTC().Format(time.RFC3339)}
	dir := filepath.Join(snapDir, m.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if len(paths) > 0 {
		if err := archive(filepath.Join(dir, "files.tar.gz"), paths, m); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}
	}
	if len(databases) > 0 {
		m.Databases = map[string]string{}
		for _, db := range databases {
			m.Databases[db] = dumpDatabase(dir, db)
		}
	}
	m.Bytes = dirSize(dir)
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o600); err != nil {
		return nil, err
	}
	pruneAuto()
	return m, nil
}

func archive(dst string, paths []string, m *snapMeta) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, root := range paths {
		werr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				m.Skipped++
				return nil
			}
			fi, err := os.Lstat(p)
			if err != nil {
				m.Skipped++
				return nil
			}
			link := ""
			switch {
			case fi.Mode()&os.ModeSymlink != 0:
				link, _ = os.Readlink(p)
			case fi.Mode().IsRegular(), fi.IsDir():
			default:
				return nil // sockets, devices, pipes
			}
			hdr, err := tar.FileInfoHeader(fi, link)
			if err != nil {
				m.Skipped++
				return nil
			}
			hdr.Name = strings.TrimPrefix(p, "/")
			if fi.IsDir() {
				hdr.Name += "/"
			}
			if !fi.Mode().IsRegular() {
				return tw.WriteHeader(hdr)
			}
			src, err := os.Open(p)
			if err != nil {
				m.Skipped++
				return nil
			}
			defer src.Close()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			n, err := io.CopyN(tw, src, hdr.Size)
			if err == io.EOF {
				// The file shrank while we read it (a rotating log): pad so the archive stays valid.
				_, err = io.CopyN(tw, zeros{}, hdr.Size-n)
				m.Skipped++
			}
			if err != nil {
				return err
			}
			m.Files++
			return nil
		})
		if werr != nil {
			return werr
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Sync()
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func dumpDatabase(dir, db string) string {
	if !regexp.MustCompile(`^[A-Za-z0-9_$-]+$`).MatchString(db) {
		return "error: bad database name"
	}
	bin, err := exec.LookPath("mysqldump")
	if err != nil {
		if bin, err = exec.LookPath("mariadb-dump"); err != nil {
			return "error: no mysqldump on this server"
		}
	}
	name := "db-" + db + ".sql.gz"
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "error: " + err.Error()
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	cmd := exec.Command(bin, "--single-transaction", "--routines", "--triggers", "--events", db)
	cmd.Stdout = gz
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	gz.Close()
	if err != nil {
		return "error: " + strings.TrimSpace(stderr.String()+" "+err.Error())
	}
	return name
}

func dirSize(dir string) (n int64) {
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return
}

func readSnapshots() []snapMeta {
	entries, _ := os.ReadDir(snapDir)
	var out []snapMeta
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(snapDir, e.Name(), "meta.json"))
		var m snapMeta
		if err == nil && json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func pruneAuto() {
	n := 0
	for _, m := range readSnapshots() {
		if m.Label == "auto" || m.Label == "pre-rollback" {
			if n++; n > keepAuto {
				os.RemoveAll(filepath.Join(snapDir, m.ID))
			}
		}
	}
}

func listSnapshots() (any, error) {
	list := readSnapshots()
	var total int64
	for _, m := range list {
		total += m.Bytes
	}
	return map[string]any{"snapshots": list, "total_bytes": total, "folder": snapDir}, nil
}

func rollback(raw json.RawMessage) (any, error) {
	var a struct {
		ID    string   `json:"id"`
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" || a.ID == "." || a.ID == ".." || filepath.Base(a.ID) != a.ID {
		return nil, errors.New("id is required")
	}
	b, err := os.ReadFile(filepath.Join(snapDir, filepath.Base(a.ID), "meta.json"))
	if err != nil {
		return nil, errors.New("no snapshot with that id")
	}
	var m snapMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	scope := m.Paths
	if len(a.Paths) > 0 {
		scope = a.Paths
	}
	within := func(p string) bool {
		for _, s := range scope {
			s = filepath.Clean(s)
			if p == s || strings.HasPrefix(p, s+"/") {
				return true
			}
		}
		return false
	}
	// Take a snapshot of what is there now, so the rollback itself can be undone.
	pre, err := takeSnapshot(scope, nil, "pre-rollback")
	if err != nil {
		return nil, fmt.Errorf("could not save the current state first, nothing changed: %w", err)
	}
	f, err := os.Open(filepath.Join(snapDir, m.ID, "files.tar.gz"))
	if err != nil {
		return nil, errors.New("this snapshot has no files (databases only); restore the dump with run")
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	restored, failed := 0, []string{}
	var dirs []*tar.Header
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		target := filepath.Clean("/" + hdr.Name)
		if !within(target) {
			continue
		}
		if err := restoreEntry(target, hdr, tr); err != nil {
			failed = append(failed, target+": "+err.Error())
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			dirs = append(dirs, hdr)
		}
		restored++
	}
	// Directory times last, after their contents were written.
	for _, h := range dirs {
		os.Chtimes(filepath.Clean("/"+h.Name), h.ModTime, h.ModTime)
	}
	return map[string]any{"restored": restored, "failed": failed, "undo_with": pre.ID, "databases": m.Databases}, nil
}

func restoreEntry(target string, hdr *tar.Header, r io.Reader) error {
	full := hdr.FileInfo().Mode()
	mode := full.Perm()
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(target, mode); err != nil {
			return err
		}
	case tar.TypeSymlink:
		os.Remove(target)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(hdr.Linkname, target); err != nil {
			return err
		}
		return os.Lchown(target, hdr.Uid, hdr.Gid)
	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		tmp := target + ".sudowhizzy-tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		f.Close()
		if err := os.Rename(tmp, target); err != nil {
			os.Remove(tmp)
			return err
		}
	default:
		return nil
	}
	os.Chown(target, hdr.Uid, hdr.Gid) // chown clears setuid, so chmod after
	os.Chmod(target, mode|full&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky))
	os.Chtimes(target, hdr.ModTime, hdr.ModTime)
	return nil
}

// --- self-update
//
// The hub sends the latest version on every poll. When it differs, and no
// command is running, the agent fetches the signed manifest, checks the
// signature and the binary's SHA-256, keeps the old binary as .prev, swaps in
// the new one and exits; systemd starts the new version. Jobs run in their own
// systemd units, so they keep running.

var (
	active      atomic.Int32
	lastTried   string
	lastTriedAt time.Time
)

type manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // arch -> sha256 hex
}

func maybeUpdate(c config, latest string) {
	if latest == version || active.Load() > 0 || (latest == lastTried && time.Since(lastTriedAt) < 15*time.Minute) {
		return
	}
	lastTried, lastTriedAt = latest, time.Now()
	if err := selfUpdate(c, latest); err != nil {
		fmt.Fprintln(os.Stderr, "update to", latest, "failed:", err)
		return
	}
	fmt.Fprintln(os.Stderr, "updated to", latest, "; restarting")
	os.Exit(0)
}

func fetch(url string, limit int64) ([]byte, error) {
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

func selfUpdate(c config, latest string) error {
	pub, err := base64.StdEncoding.DecodeString(releaseKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad built-in release key")
	}
	raw, err := fetch(c.Hub+"/dl/manifest.json", 1<<16)
	if err != nil {
		return err
	}
	sigB64, err := fetch(c.Hub+"/dl/manifest.sig", 1<<10)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || !ed25519.Verify(pub, raw, sig) {
		return errors.New("manifest signature does not match")
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Version != latest {
		return fmt.Errorf("manifest is %s, hub said %s", m.Version, latest)
	}
	want := m.Files[runtime.GOARCH]
	if want == "" {
		return errors.New("no build for " + runtime.GOARCH)
	}
	bin, err := fetch(c.Hub+"/dl/sudowhizzy-agent-linux-"+runtime.GOARCH, 64<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != want {
		return errors.New("binary checksum does not match the signed manifest")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(self); err == nil {
		os.WriteFile(self+".prev", old, 0o755)
	}
	tmp := self + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	// Never swap in a binary that cannot start: it must run and name the version the manifest promised.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tmp, "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != latest {
		os.Remove(tmp)
		return fmt.Errorf("the new binary does not start (%v, %q); keeping %s", err, strings.TrimSpace(string(out)), version)
	}
	return os.Rename(tmp, self)
}

// --- background jobs
//
// Long commands run as transient systemd units (sw-job-<id>), so they outlive
// the tool call, the agent and agent updates. Output and exit code go to
// files in jobsDir/<id>.

var jobIDClean = regexp.MustCompile(`^[0-9a-z-]{8,40}$`)

func newJobID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func jobStart(raw json.RawMessage) (any, error) {
	var a struct {
		Command string `json:"command"`
		Cwd     string `json:"cwd"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || strings.TrimSpace(a.Command) == "" {
		return nil, errors.New("command is required")
	}
	pruneJobs()
	id := newJobID()
	dir := filepath.Join(jobsDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(map[string]string{"id": id, "name": a.Name, "command": a.Command, "cwd": a.Cwd, "started": time.Now().UTC().Format(time.RFC3339)})
	os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600)
	log := filepath.Join(dir, "output.log")
	os.WriteFile(log, nil, 0o600)
	exitFile := filepath.Join(dir, "exit_code")
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	env := append(append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "TERM=dumb"), homeEnv()...)
	if systemdJobs {
		args := []string{"--unit=sw-job-" + id, "--collect", "--quiet",
			"--property=StandardOutput=append:" + log, "--property=StandardError=append:" + log,
			"--setenv=DEBIAN_FRONTEND=noninteractive", "--setenv=TERM=dumb", "--setenv=HOME=" + agentHome,
			"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
		if a.Cwd != "" {
			args = append(args, "--working-directory="+a.Cwd)
		}
		// The outer shell records the exit code once the command ends.
		args = append(args, shell, "-c", `"$0" -c "$1"; echo $? > "$2"`, shell, a.Command, exitFile)
		out, err := exec.Command("systemd-run", args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("could not start: %s %v", strings.TrimSpace(string(out)), err)
		}
		return map[string]any{"job_id": id, "log": log}, nil
	}
	// No systemd for us: run the command in its own session, so it outlives this
	// tool call and the agent. The pid file marks it for status and stop.
	logF, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logF.Close()
	cmd := exec.Command(shell, "-c", `"$0" -c "$1" >> "$2" 2>&1; echo $? > "$3"`, shell, a.Command, log, exitFile)
	cmd.Dir = a.Cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // own session, so a stop kills the whole tree
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	os.WriteFile(filepath.Join(dir, "pid"), []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0o600)
	go func() { cmd.Wait() }() // reap without blocking; the exit code is already in the file
	return map[string]any{"job_id": id, "log": log}, nil
}

func jobPid(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "pid"))
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	return pid
}

func jobDir(raw json.RawMessage) (string, string, error) {
	var a struct {
		ID string `json:"job_id"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || !jobIDClean.MatchString(a.ID) {
		return "", "", errors.New("job_id is required")
	}
	dir := filepath.Join(jobsDir, a.ID)
	if _, err := os.Stat(dir); err != nil {
		return "", "", errors.New("no job with that id")
	}
	return a.ID, dir, nil
}

func jobStatus(id, dir string) (string, any) {
	if b, err := os.ReadFile(filepath.Join(dir, "exit_code")); err == nil {
		code := strings.TrimSpace(string(b))
		var n int
		if _, err := fmt.Sscanf(code, "%d", &n); err == nil {
			return "finished", n
		}
		return "finished", code
	}
	if systemdJobs {
		if exec.Command("systemctl", "is-active", "--quiet", "sw-job-"+id).Run() == nil {
			return "running", nil
		}
	} else if pid := jobPid(dir); pid > 0 && syscall.Kill(pid, 0) == nil {
		return "running", nil
	}
	return "ended without an exit code (killed, or the server restarted)", nil
}

func jobOutput(raw json.RawMessage) (any, error) {
	id, dir, err := jobDir(raw)
	if err != nil {
		return nil, err
	}
	var a struct {
		Offset *int64 `json:"offset"`
	}
	json.Unmarshal(raw, &a)
	status, code := jobStatus(id, dir)
	f, err := os.Open(filepath.Join(dir, "output.log"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, _ := f.Stat()
	size := fi.Size()
	const chunk = 48 << 10
	from := max(size-chunk, 0) // default: the tail
	if a.Offset != nil {
		from = min(max(*a.Offset, 0), size)
	}
	f.Seek(from, io.SeekStart)
	b, _ := io.ReadAll(io.LimitReader(f, chunk))
	var meta map[string]string
	if m, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
		json.Unmarshal(m, &meta)
	}
	started, _ := time.Parse(time.RFC3339, meta["started"])
	return map[string]any{
		"job_id": id, "status": status, "exit_code": code, "command": meta["command"],
		"running_for_s": int(time.Since(started).Seconds()), "output_from": from, "next_offset": from + int64(len(b)), "output_bytes": size,
		"output": strings.ToValidUTF8(string(b), "?"),
	}, nil
}

func jobStop(raw json.RawMessage) (any, error) {
	id, dir, err := jobDir(raw)
	if err != nil {
		return nil, err
	}
	if status, _ := jobStatus(id, dir); status != "running" {
		return map[string]any{"job_id": id, "status": status}, nil
	}
	if systemdJobs {
		exec.Command("systemctl", "stop", "sw-job-"+id).Run()
	} else if pid := jobPid(dir); pid > 0 {
		syscall.Kill(-pid, syscall.SIGKILL)
	}
	os.WriteFile(filepath.Join(dir, "exit_code"), []byte("stopped\n"), 0o600)
	return map[string]any{"job_id": id, "status": "stopped"}, nil
}

func jobList() (any, error) {
	entries, _ := os.ReadDir(jobsDir)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	var out []map[string]any
	for _, e := range entries {
		if len(out) == 20 {
			break
		}
		dir := filepath.Join(jobsDir, e.Name())
		var meta map[string]string
		if m, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
			json.Unmarshal(m, &meta)
		}
		status, code := jobStatus(e.Name(), dir)
		out = append(out, map[string]any{"job_id": e.Name(), "name": meta["name"], "command": meta["command"], "started": meta["started"], "status": status, "exit_code": code})
	}
	return map[string]any{"jobs": out}, nil
}

func pruneJobs() {
	entries, _ := os.ReadDir(jobsDir)
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > 7*24*time.Hour {
			dir := filepath.Join(jobsDir, e.Name())
			if status, _ := jobStatus(e.Name(), dir); status != "running" {
				os.RemoveAll(dir)
			}
		}
	}
	// Database dumps hold customer data: gone after 7 days (a migration takes hours).
	dumps, _ := os.ReadDir(dumpDir)
	for _, e := range dumps {
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > 7*24*time.Hour {
			os.Remove(filepath.Join(dumpDir, e.Name()))
		}
	}
}

func atoiOr(s string, d int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return d
	}
	return n
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

func fmtSscan(s string, v any) { fmt.Sscan(strings.TrimSpace(s), v) }

func numCPU() int { return runtime.NumCPU() }
