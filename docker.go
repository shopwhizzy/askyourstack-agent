package main

// Sites that run in Docker containers (docker compose, Coolify, Dokploy and the
// like). A site is found when its files are mounted into a running container
// from the host, as a folder or a volume: the files are read here on the host,
// its command line tool runs inside the container (docker exec), and its
// database host, which is a name only containers know, is turned into the
// address of the container that answers to it.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type dockerNet struct {
	IP      string
	Aliases []string
}

type dockerBox struct {
	ID, Name, Service string
	Mounts            []dockerMount
	Env               map[string]string
	Labels            map[string]string
	Nets              map[string]dockerNet
}

type dockerMount struct{ Source, Destination string }

// boxMount: a folder on the host and where a container sees it.
type boxMount struct {
	box   *dockerBox
	mount dockerMount
}

func (m *boxMount) inside(hostPath string) string {
	rel, err := filepath.Rel(m.mount.Source, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return m.mount.Destination
	}
	return filepath.Join(m.mount.Destination, rel)
}

var dockerCache struct {
	sync.Mutex
	at    time.Time
	boxes []*dockerBox
}

func parseDockerInspect(raw []byte) []*dockerBox {
	var list []struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Env    []string
			Labels map[string]string
		}
		Mounts          []struct{ Type, Source, Destination string }
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string
				Aliases   []string
				DNSNames  []string
			}
		}
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []*dockerBox
	for _, c := range list {
		b := &dockerBox{ID: c.ID, Name: strings.TrimPrefix(c.Name, "/"), Env: map[string]string{}, Labels: c.Config.Labels, Nets: map[string]dockerNet{}}
		b.Service = c.Config.Labels["com.docker.compose.service"]
		for _, e := range c.Config.Env {
			if k, v, ok := strings.Cut(e, "="); ok {
				b.Env[k] = v
			}
		}
		for _, m := range c.Mounts {
			if (m.Type == "bind" || m.Type == "volume") && strings.HasPrefix(m.Source, "/") {
				b.Mounts = append(b.Mounts, dockerMount{m.Source, m.Destination})
			}
		}
		for name, n := range c.NetworkSettings.Networks {
			b.Nets[name] = dockerNet{IP: n.IPAddress, Aliases: append(n.Aliases, n.DNSNames...)}
		}
		out = append(out, b)
	}
	return out
}

// dockerBoxes lists the running containers, read at most once a minute.
func dockerBoxes() []*dockerBox {
	dockerCache.Lock()
	defer dockerCache.Unlock()
	if time.Since(dockerCache.at) < time.Minute {
		return dockerCache.boxes
	}
	dockerCache.at, dockerCache.boxes = time.Now(), nil
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ids, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc").Output()
	if err != nil || len(strings.Fields(string(ids))) == 0 {
		return nil
	}
	raw, err := exec.CommandContext(ctx, "docker", append([]string{"inspect"}, strings.Fields(string(ids))...)...).Output()
	if err != nil {
		return nil
	}
	dockerCache.boxes = parseDockerInspect(raw)
	return dockerCache.boxes
}

// Mounts that are never a site: the system's own folders and the Docker socket.
var notSiteMount = regexp.MustCompile(`^/(proc|sys|dev|run|etc|var/run|var/lib/mysql|var/lib/postgresql|usr|bin|lib|boot)(/|$)|docker\.sock$`)

// dockerFolders: every folder mounted into a container that may hold a site,
// itself and one level down.
func dockerFolders() []struct {
	dir string
	in  *boxMount
} {
	var out []struct {
		dir string
		in  *boxMount
	}
	for _, b := range dockerBoxes() {
		for _, m := range b.Mounts {
			if notSiteMount.MatchString(m.Source) || m.Source == "/" || !isDir(m.Source) {
				continue
			}
			in := &boxMount{b, m}
			out = append(out, struct {
				dir string
				in  *boxMount
			}{m.Source, in})
			kids, _ := os.ReadDir(m.Source)
			for i, k := range kids {
				if i >= 60 {
					break
				}
				if k.IsDir() {
					out = append(out, struct {
						dir string
						in  *boxMount
					}{filepath.Join(m.Source, k.Name()), in})
				}
			}
		}
	}
	return out
}

// reach turns a database host as the container knows it (a service name, or
// localhost for a database in the same container) into an address the host can dial.
func (b *dockerBox) reach(host string, all []*dockerBox) string {
	if host == "host.docker.internal" || host == "gateway.docker.internal" {
		return "127.0.0.1" // the database runs on this machine itself
	}
	if host == "" || host == "localhost" || host == "127.0.0.1" {
		for _, n := range b.Nets {
			if n.IP != "" {
				return n.IP
			}
		}
		return host
	}
	for _, other := range all {
		for net, n := range other.Nets {
			if _, shared := b.Nets[net]; !shared || n.IP == "" {
				continue
			}
			if other.Name == host || other.Service == host {
				return n.IP
			}
			for _, a := range n.Aliases {
				if a == host {
					return n.IP
				}
			}
		}
	}
	return host
}

var (
	traefikHost = regexp.MustCompile("Host\\(([^)]*)\\)")
	backticked  = regexp.MustCompile("`([^`]+)`")
)

// domains a reverse proxy routes to this container, from the labels and
// variables Traefik, Caddy and nginx-proxy read (Coolify and Dokploy write them).
func (b *dockerBox) domains() []string {
	var out []string
	add := func(v string) {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if h := hostName(part); h != "" {
				out = addOnce(out, h)
			}
		}
	}
	for k, v := range b.Labels {
		switch {
		case strings.HasPrefix(k, "traefik.") && strings.HasSuffix(k, ".rule"):
			for _, m := range traefikHost.FindAllStringSubmatch(v, -1) {
				for _, h := range backticked.FindAllStringSubmatch(m[1], -1) {
					add(h[1])
				}
			}
		case k == "caddy" || regexp.MustCompile(`^caddy_\d+$`).MatchString(k):
			add(v)
		}
	}
	for _, k := range []string{"VIRTUAL_HOST", "LETSENCRYPT_HOST"} {
		add(b.Env[k])
	}
	return out
}

// uidOf: the numeric owner of a folder, as docker exec -u takes it. Names differ
// between the host and the container; numbers do not.
func uidOf(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.Itoa(int(st.Uid)) + ":" + strconv.Itoa(int(st.Gid))
}

// argv to run a site's command: as it is on the host, wrapped in docker exec for a container.
func (s *site) inBox(argv []string) []string {
	if s.Container == "" {
		return argv
	}
	pre := []string{"docker", "exec", "-w", s.InPath}
	if s.uid != "" {
		pre = append(pre, "-u", s.uid)
	}
	return append(append(pre, s.Container), argv...)
}

// command runs argv in the site's folder as the site's owner, on the host or in its container.
func (s *site) command(ctx context.Context, argv ...string) *exec.Cmd {
	if s.Container != "" {
		full := s.inBox(argv)
		cmd := exec.CommandContext(ctx, full[0], full[1:]...)
		cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
		return cmd
	}
	return asOwner(ctx, s.Owner, s.Root, argv[0], argv[1:]...)
}

// has: is a program there for this site (in its container, or on the host)?
func (s *site) has(program string) bool {
	if s.Container == "" {
		_, err := exec.LookPath(program)
		return err == nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "exec", s.Container, "sh", "-c", "command -v "+shellQuote(program)).Run() == nil
}
