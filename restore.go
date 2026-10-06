package main

// Loading a database dump back: the undo for db_dump, table_dump and the copies
// the hub takes before an approved destructive statement. A restore first dumps
// the database as it is now (before-restore-...), so the restore itself can be
// undone, then feeds the file to the client with the site's own credentials.

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Op "dumps": what is in the dumps folder, newest first.
func listDumps(json.RawMessage) (any, error) {
	entries, _ := os.ReadDir(dumpDir)
	type dump struct {
		File    string `json:"file"`
		Kind    string `json:"kind"`
		SizeMB  int64  `json:"size_mb"`
		Made    string `json:"made"`
		AgeDays int    `json:"age_days"`
	}
	var out []dump
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() || !dumpName(e.Name()) {
			continue
		}
		kind := "db_dump"
		switch {
		case strings.HasPrefix(e.Name(), "before-restore-"):
			kind = "copy taken before a restore"
		case strings.HasPrefix(e.Name(), "before-"):
			kind = "copy of tables taken before an approved change"
		}
		out = append(out, dump{filepath.Join(dumpDir, e.Name()), kind, (fi.Size() + 1<<20 - 1) >> 20, fi.ModTime().UTC().Format(time.RFC3339), int(time.Since(fi.ModTime()).Hours() / 24)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Made > out[j].Made })
	return map[string]any{"folder": dumpDir, "dumps": out, "note": "Files here are deleted after 7 days. db_restore loads one back into its site's database; the AI can also name any other .sql or .sql.gz file on the server (a backup the user keeps)."}, nil
}

func dumpName(n string) bool {
	return strings.HasSuffix(n, ".sql") || strings.HasSuffix(n, ".sql.gz")
}

// Op "db_restore": a background job running `sudowhizzy-agent dbrestore <site> <file>`.
func dbRestoreStart(raw json.RawMessage) (any, error) {
	var a struct{ Site, File string }
	json.Unmarshal(raw, &a)
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.db.Name == "" {
		return nil, errors.New("could not read the database settings of " + s.Root)
	}
	file := strings.TrimSpace(a.File)
	if file == "" {
		return nil, errors.New("pass file: the .sql or .sql.gz to load (list_dumps shows the dumps on this server)")
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(dumpDir, filepath.Base(file))
	}
	file = filepath.Clean(file)
	fi, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return nil, errors.New(file + " is not a file with content")
	}
	if !dumpName(file) {
		return nil, errors.New(file + " is not a .sql or .sql.gz file")
	}
	if err := os.MkdirAll(dumpDir, 0o700); err != nil {
		return nil, err
	}
	self, _ := os.Executable()
	j, _ := json.Marshal(map[string]string{"command": shellQuote(self) + " dbrestore " + shellQuote(s.Root) + " " + shellQuote(file), "name": "db_restore " + s.db.Name})
	r, err := jobStart(j)
	if err != nil {
		return nil, err
	}
	m := r.(map[string]any)
	m["file"], m["database"], m["site"] = file, s.db.Name, s.Root
	m["note"] = "The database as it is now is dumped first to " + dumpDir + " (before-restore-...), then the file is loaded. Tables in the file replace the ones with the same name; tables the file does not mention stay. Follow with job_output."
	return m, nil
}

func dbRestoreNow(root, file string) error {
	s, err := pickSite(root)
	if err != nil {
		return err
	}
	if s.db == nil || s.db.Name == "" {
		return errors.New("no database settings")
	}
	bin, err := mysqlBinary()
	if err != nil {
		return err
	}
	// The way back from this restore: the database as it is before it.
	before := filepath.Join(dumpDir, "before-restore-"+s.db.Name+"-"+time.Now().UTC().Format("20060102-150405")+".sql.gz")
	fmt.Println("saving the database as it is now to", before)
	if err := dbDumpNow(root, before); err != nil {
		return fmt.Errorf("the copy before the restore failed, so nothing was loaded: %v", err)
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	cnf, err := writeMyCnf(s.db)
	if err != nil {
		return err
	}
	defer os.Remove(cnf)
	load := func(defaults string) (string, error) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		var in io.Reader = f
		if strings.HasSuffix(file, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return "", fmt.Errorf("%s is not a gzip file: %v", file, err)
			}
			defer gz.Close()
			in = gz
		}
		var stderr strings.Builder
		cmd := exec.Command(bin, defaults+cnf, "--default-character-set=utf8mb4", s.db.Name)
		cmd.Stdin = in
		cmd.Stdout = os.Stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stderr.String(), err
	}
	started := time.Now()
	fmt.Println("loading", file, "into", s.db.Name)
	// The client refuses a broken my.cnf before it reads any input, so trying again is safe.
	msg, err := load(defaultsExtra)
	if err != nil && brokenDefaults(fmt.Errorf("%s", msg)) {
		msg, err = load(defaultsOnly)
	}
	fmt.Print(msg)
	if err != nil {
		return fmt.Errorf("the load stopped with an error after %s; the database may hold a mix of old and new tables. The copy from before is %s: load it with db_restore to go back", time.Since(started).Round(time.Second), before)
	}
	fmt.Printf("restored %s from %s in %s; the copy from before is %s\n", s.db.Name, file, time.Since(started).Round(time.Second), before)
	return nil
}
