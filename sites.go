package main

// Existing sites: find Magento and WordPress installs, read their database
// settings from their own config, run SQL, bin/magento and wp-cli as the
// site's owner. Database passwords stay on the server.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type dbConf struct {
	Name, User, Password, Host, Port, Socket, Prefix string
}

type site struct {
	Kind       string   `json:"kind"` // magento | wordpress
	Root       string   `json:"root"`
	Owner      string   `json:"owner"`
	Version    string   `json:"version,omitempty"`
	Domains    []string `json:"domains,omitempty"`     // from the web server's virtual hosts
	AccessLogs []string `json:"access_logs,omitempty"` // pass one to crawl_report as log
	DBName     string   `json:"database,omitempty"`
	DBHost     string   `json:"db_host,omitempty"`
	Prefix     string   `json:"table_prefix,omitempty"`
	Console    string   `json:"console,omitempty"`           // its own command line tool, run with site_console
	WebRoot    string   `json:"web_root,omitempty"`          // the folder inside the root that the web server serves
	Woo        string   `json:"woocommerce,omitempty"`       // WooCommerce's version, when the site is a shop
	Container  string   `json:"container,omitempty"`         // the Docker container that runs it
	InPath     string   `json:"path_in_container,omitempty"` // where the container sees the root
	Note       string   `json:"note,omitempty"`
	db         *dbConf
	box        *dockerBox
	env        map[string]string // the container's variables, which win over .env files
	uid        string
}

const magentoMarker = "app/etc/env.php"

// Folders where sites usually live, by hosting layout. The web server's own
// configuration (vhosts.go) adds every other place.
func siteGlobs() []string {
	g := []string{
		"/var/www/*/", "/var/www/*/*/",
		"/var/www/*/*/*/", // Plesk: /var/www/vhosts/<domain>/httpdocs and its subdomain folders
		"/home/*/public_html/", "/home/*/*/", "/home/*/*/public_html/",
		"/home/*/public_html/*/",         // cPanel add-on domains
		"/home/*/htdocs/*/",              // CloudPanel
		"/home/*/webapps/*/",             // RunCloud
		"/home/*/domains/*/public_html/", // DirectAdmin
		"/home/*/web/*/public_html/",     // HestiaCP
		"/srv/*/", "/srv/www/*/", "/usr/share/nginx/html/",
		"/opt/bitnami/wordpress/", "/bitnami/wordpress/",
	}
	if !privileged {
		// A limited user's sites are somewhere under their own home, whatever the panel calls it.
		for _, d := range []string{"/", "/*/", "/*/*/", "/*/*/*/"} {
			g = append(g, agentHome+d)
		}
	}
	return g
}

func readable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// mine: the folder belongs to the user the agent runs as. A limited user's
// agent lists that user's own sites, not a neighbour's with loose permissions.
func mine(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// locateSites finds the site folders, without opening their settings.
func locateSites() []*site {
	seen := map[string]bool{}
	var out []*site
	var check func(dir string, in *boxMount)
	check = func(dir string, in *boxMount) {
		k, root := siteAt(filepath.Clean(dir))
		if k == nil || (!privileged && !mine(root)) {
			return
		}
		if k.Name == "wordpress" && !isFile(filepath.Join(root, "wp-load.php")) {
			// Only the configuration is here: the install is one folder down.
			moved := false
			kids, _ := filepath.Glob(filepath.Join(root, "*", "wp-load.php"))
			for _, kid := range kids {
				if kid = filepath.Dir(kid); !isFile(filepath.Join(kid, "wp-config.php")) {
					check(kid, in)
					moved = true
				}
			}
			if moved {
				return
			}
		}
		if real := realPath(root); !seen[real] {
			seen[real] = true
			s := &site{Kind: k.Name, Root: root}
			if in != nil {
				s.box, s.Container, s.InPath = in.box, in.box.Name, in.inside(root)
			}
			out = append(out, s)
		}
	}
	// First what is mounted into Docker containers, so those sites are known as
	// running in a container; then the usual folders of each hosting layout.
	for _, f := range dockerFolders() {
		check(f.dir, f.in)
	}
	for _, g := range siteGlobs() {
		dirs, _ := filepath.Glob(strings.TrimSuffix(g, "/"))
		for _, d := range dirs {
			check(d, nil)
		}
	}
	// What the web server serves: the folder itself, or its parent when the
	// document root is the site's pub or public folder.
	for _, v := range vhosts() {
		for _, r := range v.Roots {
			check(r, nil)
			if p := filepath.Dir(r); p != "/" && p != "." {
				check(p, nil)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	return out
}

// describeSite reads the owner, version, database settings, domains and logs.
func describeSite(s *site, all []vhost) *site {
	k := kindOf(s.Kind)
	s.Owner = ownerOf(s.Root)
	s.Version = k.Version(s.Root)
	if s.box != nil {
		s.env, s.uid = s.box.Env, uidOf(s.Root)
	}
	s.db = k.DB(s)
	if s.db != nil && s.db.Name != "" {
		if s.box != nil && s.db.Socket == "" {
			s.db.Host = s.box.reach(s.db.Host, dockerBoxes())
		}
		s.DBName, s.Prefix = s.db.Name, s.db.Prefix
		s.DBHost = s.db.Host
		if s.db.Socket != "" {
			s.DBHost += ":" + s.db.Socket
		}
	} else {
		s.db = nil
		s.Note = "its database settings could not be read (not MySQL or MariaDB, or set outside its configuration files): db_query and db_dump do not work for it"
	}
	if argv, _ := k.Console(s); argv != nil {
		s.Console = consoleName(argv)
	}
	s.WebRoot = k.WebRoot
	if k.Name == "drupal" {
		s.WebRoot = drupalWeb(s.Root)
	}
	if k.Name == "wordpress" {
		s.Woo = firstMatch(fileText(filepath.Join(s.Root, "wp-content/plugins/woocommerce/woocommerce.php")), `(?m)^\s*\*?\s*Version:\s*([0-9][^\s]*)`)
	}
	vhostsOf(s, all)
	if s.box != nil {
		for _, d := range s.box.domains() {
			s.Domains = addOnce(s.Domains, d)
		}
		note := "runs in the Docker container " + s.Container + ": magento, wp and site_console run inside it; its files belong to uid:gid " + s.uid + " (the web server's user in the container), so give files you add that owner (chown " + s.uid + ")"
		if s.Note != "" {
			note += "; " + s.Note
		}
		s.Note = note
	}
	return s
}

func findSites() []*site {
	out := locateSites()
	all := frontLogs(vhosts())
	for _, s := range out {
		describeSite(s, all)
	}
	return out
}

func listSites() (any, error) {
	return map[string]any{"sites": findSites()}, nil
}

// pickSite resolves the "site" argument: a root folder or one of the site's
// domains, or empty when the server has one site. A root outside the places
// the agent looks in works too, as long as it holds a site. Only the chosen
// site's settings are opened.
func pickSite(ref string) (*site, error) {
	all := locateSites()
	hosts := frontLogs(vhosts())
	if ref == "" {
		if len(all) == 1 {
			return describeSite(all[0], hosts), nil
		}
		if len(all) == 0 {
			return nil, errors.New("no site found on this server; give the site root (known kinds: " + kindNames() + ")")
		}
		var roots []string
		for _, s := range all {
			roots = append(roots, s.Root)
		}
		return nil, fmt.Errorf("say which site: %s", strings.Join(roots, ", "))
	}
	if !strings.HasPrefix(ref, "/") {
		name := strings.TrimPrefix(hostName(ref), "www.")
		var match []*site
		for _, s := range all {
			vhostsOf(s, hosts)
			if s.box != nil {
				s.Domains = append(s.Domains, s.box.domains()...)
			}
			for _, d := range s.Domains {
				if name != "" && strings.TrimPrefix(d, "www.") == name {
					match = append(match, s)
					break
				}
			}
			s.Domains, s.AccessLogs = nil, nil
		}
		if len(match) == 1 {
			return describeSite(match[0], hosts), nil
		}
		return nil, fmt.Errorf("no single site for %q; give the site root (see list_sites)", ref)
	}
	ref = filepath.Clean(ref)
	real := realPath(ref)
	for _, s := range all {
		if s.Root == ref || realPath(s.Root) == real {
			return describeSite(s, hosts), nil
		}
	}
	if k, root := siteAt(ref); k != nil {
		return describeSite(&site{Kind: k.Name, Root: root}, hosts), nil
	}
	return nil, fmt.Errorf("no site at %s (known kinds: %s)", ref, kindNames())
}

func ownerOf(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "root"
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "root"
	}
	u, err := user.LookupId(strconv.Itoa(int(st.Uid)))
	if err != nil {
		return "root"
	}
	return u.Username
}

func magentoVersion(root string) string {
	for _, f := range []string{"vendor/magento/magento2-base/composer.json", "vendor/mage-os/magento2-base/composer.json", "composer.json"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue
		}
		var c struct{ Name, Version string }
		if json.Unmarshal(b, &c) == nil && c.Version != "" {
			return strings.TrimSuffix(c.Name, "/magento2-base") + " " + c.Version
		}
	}
	return ""
}

var wpVersionRe = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)

func wpVersion(root string) string {
	b, _ := os.ReadFile(filepath.Join(root, "wp-includes/version.php"))
	if m := wpVersionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// Magento's env.php is PHP, so PHP reads it, running as the site owner rather
// than root in case the file was tampered with.
func magentoDB(s *site) *dbConf {
	code := `$c = (include $argv[1]); $d = $c['db']['connection']['default'] ?? []; echo json_encode(['name' => $d['dbname'] ?? '', 'user' => $d['username'] ?? '', 'password' => $d['password'] ?? '', 'host' => $d['host'] ?? 'localhost', 'prefix' => $c['db']['table_prefix'] ?? '']);`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := s.command(ctx, "php", "-r", code, "app/etc/env.php").Output()
	if err != nil {
		return nil
	}
	var d struct{ Name, User, Password, Host, Prefix string }
	if json.Unmarshal(out, &d) != nil {
		return nil
	}
	c := &dbConf{Name: d.Name, User: d.User, Password: d.Password, Prefix: d.Prefix}
	splitHost(c, d.Host)
	return c
}

var wpDefineRe = regexp.MustCompile(`define\(\s*['"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['"]\s*,\s*['"]((?:[^'"\\]|\\.)*)['"]\s*\)`)
var wpPrefixRe = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]*)['"]`)

func wpDB(s *site) *dbConf {
	root := s.Root
	b, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		b, err = os.ReadFile(filepath.Join(filepath.Dir(root), "wp-config.php"))
	}
	if err != nil {
		return nil
	}
	c := &dbConf{Prefix: "wp_"}
	host := "localhost"
	// The official Docker image's wp-config.php takes everything from the container's variables.
	if e := s.env; e != nil {
		c.Name, c.User, c.Password = e["WORDPRESS_DB_NAME"], e["WORDPRESS_DB_USER"], e["WORDPRESS_DB_PASSWORD"]
		if e["WORDPRESS_DB_HOST"] != "" {
			host = e["WORDPRESS_DB_HOST"]
		}
		if e["WORDPRESS_TABLE_PREFIX"] != "" {
			c.Prefix = e["WORDPRESS_TABLE_PREFIX"]
		}
		if c.Name == "" && e["WORDPRESS_DB_HOST"] != "" {
			c.Name = "wordpress" // the image's default
		}
	}
	for _, m := range wpDefineRe.FindAllSubmatch(b, -1) {
		v := strings.NewReplacer(`\'`, `'`, `\"`, `"`, `\\`, `\`).Replace(string(m[2]))
		switch string(m[1]) {
		case "DB_NAME":
			c.Name = v
		case "DB_USER":
			c.User = v
		case "DB_PASSWORD":
			c.Password = v
		case "DB_HOST":
			host = v
		}
	}
	if m := wpPrefixRe.FindSubmatch(b); m != nil {
		c.Prefix = string(m[1])
	}
	splitHost(c, host)
	return c
}

// "localhost", "127.0.0.1:3307" or "localhost:/run/mysqld/mysqld.sock".
func splitHost(c *dbConf, h string) {
	c.Host = h
	if i := strings.LastIndex(h, ":"); i > 0 {
		c.Host, c.Port = h[:i], h[i+1:]
		if strings.HasPrefix(c.Port, "/") {
			c.Socket, c.Port = c.Port, ""
		}
	}
}

func asOwner(ctx context.Context, owner, dir string, name string, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if !privileged || owner == "" || owner == "root" || owner == agentUser() {
		cmd = exec.CommandContext(ctx, name, args...)
	} else {
		cmd = exec.CommandContext(ctx, "runuser", append([]string{"-u", owner, "--", name}, args...)...)
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	return cmd
}

func mysqlBinary() (string, error) {
	for _, b := range []string{"mariadb", "mysql"} {
		if p, err := exec.LookPath(b); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no mysql or mariadb client on this server")
}

// --- SQL

func dbQuery(raw json.RawMessage) (any, error) {
	var a struct {
		Site     string `json:"site"`
		SQL      string `json:"sql"`
		ReadOnly bool   `json:"read_only"`
		MaxRows  int    `json:"max_rows"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || strings.TrimSpace(a.SQL) == "" {
		return nil, errors.New("sql is required")
	}
	if a.MaxRows <= 0 || a.MaxRows > 1000 {
		a.MaxRows = 200
	}
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.db.Name == "" {
		return nil, errors.New("could not read the database settings of " + s.Root)
	}
	bin, err := mysqlBinary()
	if err != nil {
		return nil, err
	}
	cnf, err := writeMyCnf(s.db)
	if err != nil {
		return nil, err
	}
	defer os.Remove(cnf)

	stmt := strings.TrimRight(strings.TrimSpace(a.SQL), "; \n\t")
	script := stmt + ";\n"
	if a.ReadOnly {
		// The hub sorted this as a read; the database enforces it too.
		script = "SET SESSION TRANSACTION READ ONLY;\nSTART TRANSACTION READ ONLY;\n" + script + "COMMIT;\n"
	} else {
		script += "SELECT ROW_COUNT() AS affected_rows;\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var cols []string
	var rows [][]string
	truncated := false
	run := func(defaults string) error {
		cols, rows, truncated = nil, nil, false
		cmd := exec.CommandContext(ctx, bin, defaults+cnf, "--batch", "--default-character-set=utf8mb4", s.db.Name)
		cmd.Stdin = strings.NewReader(script)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			fields := strings.Split(sc.Text(), "\t")
			for i, v := range fields {
				fields[i] = unescapeTSV(v)
			}
			if cols == nil {
				cols = fields
				continue
			}
			if len(rows) >= a.MaxRows {
				truncated = true
				continue // drain
			}
			rows = append(rows, fields)
		}
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(stderr.String()+" "+err.Error()))
		}
		return nil
	}
	err = run(defaultsExtra)
	if err != nil && brokenDefaults(err) {
		err = run(defaultsOnly)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"site": s.Root, "database": s.db.Name, "columns": cols, "rows": rows, "row_count": len(rows), "truncated": truncated, "read_only": a.ReadOnly}, nil
}

// The client normally also reads the server's own my.cnf files (they may name
// the socket). Where one of those holds a setting the client does not know, as
// some hosting panels' do, it refuses to start: then only our file is read.
const (
	defaultsExtra = "--defaults-extra-file="
	defaultsOnly  = "--defaults-file="
)

func brokenDefaults(err error) bool {
	return strings.Contains(err.Error(), "unknown variable") || strings.Contains(err.Error(), "unknown option")
}

// Credentials in a private file, never on the command line where ps would show them.
func writeMyCnf(db *dbConf) (string, error) {
	f, err := os.CreateTemp("", "sw-my-*.cnf")
	if err != nil {
		return "", err
	}
	os.Chmod(f.Name(), 0o600)
	q := func(v string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"` }
	fmt.Fprintf(f, "[client]\nuser=%s\npassword=%s\n", q(db.User), q(db.Password))
	if db.Socket != "" {
		fmt.Fprintf(f, "socket=%s\n", q(db.Socket))
	} else {
		fmt.Fprintf(f, "host=%s\n", q(db.Host))
		if db.Port != "" {
			fmt.Fprintf(f, "port=%s\n", db.Port)
		}
	}
	return f.Name(), f.Close()
}

// --- database dump for migrations: a background job running
// `sudowhizzy-agent dbdump <site> <file>`, with the site's own credentials.

func dbDumpStart(raw json.RawMessage) (any, error) {
	var a struct{ Site string }
	json.Unmarshal(raw, &a)
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.db.Name == "" {
		return nil, errors.New("could not read the database settings of " + s.Root)
	}
	if err := os.MkdirAll(dumpDir, 0o700); err != nil {
		return nil, err
	}
	out := filepath.Join(dumpDir, s.db.Name+"-"+time.Now().UTC().Format("20060102-150405")+".sql.gz")
	self, _ := os.Executable()
	j, _ := json.Marshal(map[string]string{"command": shellQuote(self) + " dbdump " + shellQuote(s.Root) + " " + shellQuote(out), "name": "db_dump " + s.db.Name})
	r, err := jobStart(j)
	if err != nil {
		return nil, err
	}
	m := r.(map[string]any)
	m["file"], m["database"], m["folder"] = out, s.db.Name, dumpDir
	return m, nil
}

func dbDumpNow(root, out string) error {
	s, err := pickSite(root)
	if err != nil {
		return err
	}
	if s.db == nil || s.db.Name == "" {
		return errors.New("no database settings")
	}
	bin := ""
	for _, b := range []string{"mariadb-dump", "mysqldump"} {
		if p, err := exec.LookPath(b); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return errors.New("no mysqldump or mariadb-dump on this server")
	}
	cnf, err := writeMyCnf(s.db)
	if err != nil {
		return err
	}
	defer os.Remove(cnf)
	f, err := os.OpenFile(out+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	// --no-tablespaces: site users rarely have the PROCESS privilege it would need.
	dump := func(defaults string) (string, error) {
		var stderr bytes.Buffer
		cmd := exec.Command(bin, defaults+cnf, "--single-transaction", "--quick", "--routines", "--triggers", "--no-tablespaces", "--default-character-set=utf8mb4", s.db.Name)
		cmd.Stdout = gz
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stderr.String(), err
	}
	// The client stops on a broken my.cnf before it writes anything, so trying again is safe.
	msg, err := dump(defaultsExtra)
	if err != nil && brokenDefaults(fmt.Errorf("%s", msg)) {
		msg, err = dump(defaultsOnly)
	}
	fmt.Print(msg)
	if err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	st, _ := f.Stat()
	fmt.Printf("dumped %s to %s (%d MB compressed)\n", s.db.Name, out, st.Size()>>20)
	return os.Rename(out+".part", out)
}

// --- a copy of the tables a destructive statement is about to hit. The hub asks
// for it just before an approved DROP, TRUNCATE, DELETE or UPDATE without WHERE
// runs, so "how do I undo this" has an answer: a file to load back.

var tableName = regexp.MustCompile(`^[A-Za-z0-9_$]{1,64}$`)

const tableDumpMax = 4 << 30

func tableDump(raw json.RawMessage) (any, error) {
	var a struct {
		Site   string   `json:"site"`
		Tables []string `json:"tables"`
	}
	json.Unmarshal(raw, &a)
	if len(a.Tables) == 0 || len(a.Tables) > 20 {
		return nil, errors.New("name 1 to 20 tables")
	}
	for _, t := range a.Tables {
		if !tableName.MatchString(t) {
			return nil, fmt.Errorf("%q is not a plain table name", t)
		}
	}
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.db.Name == "" {
		return nil, errors.New("could not read the database settings of " + s.Root)
	}
	// Which of them exist, and how big they are together.
	q, _ := json.Marshal(map[string]any{"site": s.Root, "read_only": true, "max_rows": 30,
		"sql": "SELECT table_name, data_length + index_length FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('" + strings.Join(a.Tables, "','") + "')"})
	res, err := dbQuery(q)
	if err != nil {
		return nil, err
	}
	var have []string
	var size int64
	for _, r := range res.(map[string]any)["rows"].([][]string) {
		if len(r) == 2 {
			have = append(have, r[0])
			n, _ := strconv.ParseInt(r[1], 10, 64)
			size += n
		}
	}
	if len(have) == 0 {
		return nil, errors.New("none of these tables exist, so there is nothing to save")
	}
	if size > tableDumpMax {
		return nil, fmt.Errorf("the tables hold %d MB, more than is copied automatically; use db_dump first", size>>20)
	}
	if err := os.MkdirAll(dumpDir, 0o700); err != nil {
		return nil, err
	}
	var st syscall.Statfs_t
	if syscall.Statfs(dumpDir, &st) == nil && int64(st.Bavail)*int64(st.Bsize) < 2*size+(64<<20) {
		return nil, errors.New("not enough free disk for a copy")
	}
	bin := ""
	for _, b := range []string{"mariadb-dump", "mysqldump"} {
		if p, err := exec.LookPath(b); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, errors.New("no mysqldump or mariadb-dump on this server")
	}
	cnf, err := writeMyCnf(s.db)
	if err != nil {
		return nil, err
	}
	defer os.Remove(cnf)
	label := have[0]
	if len(have) > 1 {
		label += fmt.Sprintf("-and-%d-more", len(have)-1)
	}
	out := filepath.Join(dumpDir, "before-"+s.db.Name+"-"+label+"-"+time.Now().UTC().Format("20060102-150405")+".sql.gz")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dump := func(defaults string) (string, error) {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return "", err
		}
		defer f.Close()
		gz := gzip.NewWriter(f)
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, append([]string{defaults + cnf, "--single-transaction", "--quick", "--no-tablespaces", "--default-character-set=utf8mb4", s.db.Name}, have...)...)
		cmd.Stdout, cmd.Stderr = gz, &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), err
		}
		return "", gz.Close()
	}
	msg, err := dump(defaultsExtra)
	if err != nil && brokenDefaults(fmt.Errorf("%s", msg)) {
		msg, err = dump(defaultsOnly)
	}
	if err != nil {
		os.Remove(out)
		return nil, fmt.Errorf("the copy failed: %s %v", strings.TrimSpace(msg), err)
	}
	fi, _ := os.Stat(out)
	client := "mysql"
	if strings.Contains(bin, "mariadb") {
		client = "mariadb"
	}
	return map[string]any{"file": out, "tables": have, "size": fmt.Sprintf("%d KB compressed", fi.Size()>>10+1),
		"restore": fmt.Sprintf("zcat %s | %s %s (as a user with rights on that database; it replaces the tables named)", shellQuote(out), client, s.db.Name), "kept": "7 days"}, nil
}

func unescapeTSV(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	return strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\0`, "\x00", `\\`, `\`).Replace(v)
}

// --- bin/magento and wp-cli

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func siteCLI(raw json.RawMessage) (any, error) {
	var a struct {
		Site       string   `json:"site"`
		Tool       string   `json:"tool"` // magento | wp
		Args       []string `json:"args"`
		Background bool     `json:"background"`
		TimeoutS   int      `json:"timeout_s"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || len(a.Args) == 0 {
		return nil, errors.New("args are required")
	}
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	var argv []string
	switch a.Tool {
	case "magento":
		if s.Kind != "magento" {
			return nil, errors.New(s.Root + " is not a Magento 2 site")
		}
		argv = append([]string{"php", "bin/magento"}, a.Args...)
	case "wp":
		if s.Kind != "wordpress" {
			return nil, errors.New(s.Root + " is not a WordPress site")
		}
		if !s.has("wp") {
			if s.Container != "" {
				return nil, errors.New("wp-cli is not in the container " + s.Container + " (the official wordpress image leaves it out); add it to the image, or work through db_query and the files")
			}
			return nil, errors.New("wp-cli is not installed; install it from https://wp-cli.org (the phar, checked with wp --info)")
		}
		argv = append([]string{"wp"}, a.Args...)
		if s.Container == "" {
			argv = append([]string{"wp", "--path=" + s.Root}, a.Args...)
		}
		if s.Owner == "root" || strings.HasPrefix(s.uid, "0:") {
			argv = append(argv, "--allow-root")
		}
	case "console":
		base, why := kindOf(s.Kind).Console(s)
		if base == nil {
			return nil, fmt.Errorf("%s (%s): %s", s.Root, kindOf(s.Kind).Label, why)
		}
		argv = append(append([]string{}, base...), a.Args...)
		// Symfony's console and artisan wait for an answer unless told not to; nobody is there to give one.
		if base[len(base)-1] != "vendor/bin/drush" && base[len(base)-1] != "cli/joomla.php" {
			quiet := false
			for _, v := range a.Args {
				quiet = quiet || v == "--no-interaction" || v == "-n"
			}
			if !quiet {
				argv = append(argv, "--no-interaction")
			}
		}
	default:
		return nil, errors.New("tool must be magento, wp or console")
	}
	if a.Background {
		full := s.inBox(argv)
		parts := make([]string, len(full))
		for i, v := range full {
			parts[i] = shellQuote(v)
		}
		line := strings.Join(parts, " ")
		if s.Container == "" {
			if privileged && s.Owner != "root" && s.Owner != agentUser() {
				line = "runuser -u " + shellQuote(s.Owner) + " -- " + line
			}
			line = "cd " + shellQuote(s.Root) + " && " + line
		}
		b, _ := json.Marshal(map[string]string{"command": line, "name": a.Tool + " " + a.Args[0]})
		return jobStart(b)
	}
	if a.TimeoutS <= 0 {
		a.TimeoutS = 240
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(min(a.TimeoutS, 1800))*time.Second)
	defer cancel()
	cmd := s.command(ctx, argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err = cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		return nil, err
	}
	return map[string]any{"site": s.Root, "as_user": s.Owner, "exit_code": code, "timed_out": ctx.Err() != nil, "seconds": time.Since(start).Seconds(), "stdout": stdout.String(), "stderr": stderr.String()}, nil
}
