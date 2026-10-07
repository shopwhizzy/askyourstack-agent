package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// A lock the server's administrator sets on the machine itself, with
// `askyourstack-agent lock`. While the lock file exists the agent answers only
// the operations that read, whatever the hub sends and whatever mode the
// server has in the dashboard. The hub classifies and gates commands; the lock
// is the one check that does not depend on the hub, so a hub that was
// compromised, or an approval given by mistake, still changes nothing on a
// locked server. `askyourstack-agent unlock` removes it. Nothing the hub sends
// can set or clear the file. Signed agent updates still apply.
var lockFile = filepath.Join(filepath.Dir(confPath), "lock") // recomputed by reloadPaths after a rename

func locked() bool { _, err := os.Stat(lockFile); return err == nil }

// readOps are the operations a locked agent still answers: they read the
// machine and write only under the agent's own state folder (reports,
// snapshots and dumps it takes itself).
var readOps = map[string]bool{
	"facts": true, "read_file": true, "snapshot": true, "list_snapshots": true,
	"job_output": true, "job_stop": true, "jobs": true, "sites": true, "health": true,
	"traffic": true, "logs": true, "crawl": true, "dumps": true, "audit_start": true,
	"audit_query": true, "malware_scan": true, "db_dump": true, "table_dump": true,
}

// lockRefuses says why a locked agent will not run this operation, or "" when
// it may run (not locked, or an operation that only reads).
func lockRefuses(op string, args json.RawMessage) string {
	if !locked() || readOps[op] {
		return ""
	}
	if op == "db_query" {
		var a struct {
			ReadOnly bool `json:"read_only"`
		}
		if json.Unmarshal(args, &a) == nil && a.ReadOnly {
			return ""
		}
	}
	return fmt.Sprintf("this server is locked by its administrator on the machine itself (askyourstack-agent lock), so the agent only reads here and refused %s. Only someone with a shell on the server can lift it, with: askyourstack-agent unlock", op)
}

func setLock(on bool) error {
	if !on {
		if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("unlocked: the agent runs changes again, within the server's mode and approvals")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(lockFile), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(lockFile, []byte("set with: askyourstack-agent lock\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("locked: the agent only reads on this server until you run: askyourstack-agent unlock")
	return nil
}
