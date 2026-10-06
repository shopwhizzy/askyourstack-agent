package main

// The daily health check: disks, memory, load, failed services, certificates,
// pending security updates, reboot needed, and per site the address and (for
// Magento) when cron last succeeded. The hub turns it into alerts.

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func health(raw json.RawMessage) (any, error) {
	var a struct {
		Rules string `json:"rules"` // from the hub: the vulnerability rules, scrambled (rules.go)
	}
	json.Unmarshal(raw, &a)
	h := map[string]any{"checked_at": time.Now().UTC().Format(time.RFC3339), "privileged": privileged}

	// Disks: real filesystems only.
	type disk struct {
		Mount    string  `json:"mount"`
		UsedPct  float64 `json:"used_pct"`
		InodePct float64 `json:"inode_pct"`
		FreeGB   float64 `json:"free_gb"`
	}
	var disks []disk
	seen := map[string]bool{}
	if f, err := os.Open("/proc/mounts"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 3 || seen[fs[0]] {
				continue
			}
			switch fs[2] {
			case "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs":
			default:
				continue
			}
			seen[fs[0]] = true
			var st syscall.Statfs_t
			if syscall.Statfs(fs[1], &st) != nil || st.Blocks == 0 {
				continue
			}
			d := disk{Mount: fs[1], UsedPct: round1(100 * float64(st.Blocks-st.Bfree) / float64(st.Blocks-st.Bfree+st.Bavail)), FreeGB: round1(float64(st.Bavail) * float64(st.Bsize) / 1e9)}
			if st.Files > 0 {
				d.InodePct = round1(100 * float64(st.Files-st.Ffree) / float64(st.Files))
			}
			disks = append(disks, d)
		}
		f.Close()
	}
	h["disks"] = disks

	if mi := keyValues("/proc/meminfo", ":"); mi != nil {
		kb := func(k string) float64 {
			var n float64
			fmtSscan(strings.TrimSuffix(mi[k], " kB"), &n)
			return n
		}
		if total := kb("MemTotal"); total > 0 {
			h["memory_available_pct"] = round1(100 * kb("MemAvailable") / total)
		}
		if st := kb("SwapTotal"); st > 0 {
			h["swap_used_pct"] = round1(100 * (st - kb("SwapFree")) / st)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		var l1 float64
		fmtSscan(strings.Fields(string(b))[0], &l1)
		h["load_per_cpu"] = round1(l1 / float64(max(1, numCPU())))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	// As root, system units. Unprivileged (shared hosting, a Plesk/cPanel jailed
	// user), the system units belong to the host and the control panel, not to
	// this user, who cannot fix or reset them, so reporting them is only noise
	// (e.g. a stale Plesk/Imunify transient unit): look only at this user's own
	// units, and only when they have a user manager.
	failedCmd := []string{"list-units", "--state=failed", "--no-legend", "--plain"}
	if !privileged {
		if _, err := exec.LookPath("systemctl"); err != nil || exec.CommandContext(ctx, "systemctl", "--user", "show-environment").Run() != nil {
			failedCmd = nil // no user manager: skip failed-unit checks entirely
		} else {
			failedCmd = append([]string{"--user"}, failedCmd...)
		}
	}
	if failedCmd != nil {
		if out, err := exec.CommandContext(ctx, "systemctl", failedCmd...).Output(); err == nil {
			var failed []string
			for _, l := range strings.Split(string(out), "\n") {
				if fs := strings.Fields(l); len(fs) > 0 && !strings.HasPrefix(fs[0], "sw-job-") {
					failed = append(failed, fs[0])
				}
			}
			h["failed_units"] = failed
		}
	}

	// Certificates Let's Encrypt manages here.
	type cert struct {
		Name     string `json:"name"`
		Expires  string `json:"expires"`
		DaysLeft int    `json:"days_left"`
	}
	var certs []cert
	files, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
	for _, cf := range files {
		b, err := os.ReadFile(cf)
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(b); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				certs = append(certs, cert{filepath.Base(filepath.Dir(cf)), c.NotAfter.UTC().Format("2006-01-02"), int(time.Until(c.NotAfter).Hours() / 24)})
			}
		}
	}
	h["certificates"] = certs

	// Pending security updates and reboot needed. System-wide and fixed only with
	// root, so skip them for an unprivileged agent: the jailed user cannot patch
	// or reboot the host, and it is usually the provider's job on shared hosting.
	if !privileged {
		// nothing here
	} else if _, err := exec.LookPath("dnf"); err == nil {
		if out, err := exec.CommandContext(ctx, "dnf", "-q", "--setopt=timeout=20", "updateinfo", "list", "--security").Output(); err == nil {
			h["security_updates"] = countLines(string(out))
		}
		h["reboot_required"] = exec.CommandContext(ctx, "dnf", "-q", "needs-restarting", "-r").Run() != nil && commandExists("dnf")
	} else if _, err := exec.LookPath("apt-get"); err == nil {
		if out, err := exec.CommandContext(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade").Output(); err == nil {
			n := 0
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, "Inst ") && strings.Contains(l, "security") {
					n++
				}
			}
			h["security_updates"] = n
		}
		_, err := os.Stat("/var/run/reboot-required")
		h["reboot_required"] = err == nil
	}

	// What owners assume is watched (watch.go).
	h["backups"] = backupsFound(time.Now())
	if o := oomKills(); o != nil {
		h["out_of_memory"] = o
	}
	if f := fpmSaturation(time.Now()); f != nil {
		h["php_workers_full"] = f
	}

	// Sites: their address, and Magento cron.
	var sites []map[string]any
	found := findSites()
	if a.Rules != "" {
		h["vulnerabilities"] = knownHoles(a.Rules, found)
	}
	// What is installed, for the hub's vulnerability feeds (Pro and Agency match it there).
	if sw := softwareOf(found); len(sw) > 0 {
		h["software"] = sw
	}
	for _, s := range found {
		if s.db != nil && s.db.Name != "" && h["database"] == nil {
			if c := dbConnections(s); c != nil {
				h["database"] = c
			}
		}
		info := map[string]any{"kind": s.Kind, "root": s.Root}
		k := kindOf(s.Kind)
		if url := k.Address(s); url != "" {
			info["url"] = url
		} else if s.db == nil {
			info["error"] = "could not read the database settings"
		}
		// Is its scheduler alive: minutes since it last finished a job.
		if k.CronSQL != nil {
			if v := sqlValue(s, k.CronSQL(s)); v != "" {
				var m int
				fmtSscan(v, &m)
				info["cron_minutes_ago"] = m
			}
		}
		// A WooCommerce shop: background tasks (emails, renewals, stock) that are late or failed.
		if s.Woo != "" {
			info["woocommerce"] = s.Woo
			t := s.Prefix + "actionscheduler_actions"
			late := sqlValue(s, "SELECT COUNT(*) FROM "+t+" WHERE status = 'pending' AND scheduled_date_gmt < UTC_TIMESTAMP() - INTERVAL 1 HOUR")
			failed := sqlValue(s, "SELECT COUNT(*) FROM "+t+" WHERE status = 'failed' AND last_attempt_gmt > UTC_TIMESTAMP() - INTERVAL 1 DAY")
			if late != "" {
				var a, b int
				fmtSscan(late, &a)
				fmtSscan(failed, &b)
				info["background_tasks"] = map[string]int{"late": a, "failed_24h": b}
			}
		}
		sites = append(sites, info)
	}
	h["sites"] = sites
	return h, nil
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func countLines(s string) int {
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

func commandExists(c string) bool { _, err := exec.LookPath(c); return err == nil }
