package main

// Image conversion as a background job: WebP (or AVIF) copies next to the
// originals in a site's upload folders, made by the tools the server has
// (cwebp, avifenc, ImageMagick, vips) and run as the site's owner so the new
// files belong to the site. Originals are never touched; a copy that is not
// smaller is removed again. Serving the copies is the web server's job: the
// hub's tool text gives the nginx and Apache lines.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type imagesArgs struct {
	Site     string   `json:"site"`
	Root     string   `json:"root"`
	Owner    string   `json:"owner"`
	Folders  []string `json:"folders"`
	Format   string   `json:"format"`
	Quality  int      `json:"quality"`
	MaxFiles int      `json:"max_files"`
	DryRun   bool     `json:"dry_run"`
	Tool     string   `json:"tool"`
}

const (
	imagesMaxFiles = 20000
	imagesMaxBytes = 25 << 20
	imagesMinBytes = 8 << 10
	imagesTimeout  = 60 * time.Minute
)

// The encoder for a format, as argv with {IN}, {OUT} and {Q} placeholders, or why there is none.
func imageTool(format string) ([]string, string, error) {
	have := func(n string) bool { _, err := exec.LookPath(n); return err == nil }
	switch format {
	case "webp":
		switch {
		case have("cwebp"):
			return []string{"cwebp", "-quiet", "-q", "{Q}", "-metadata", "none", "{IN}", "-o", "{OUT}"}, "cwebp", nil
		case have("magick"):
			return []string{"magick", "{IN}", "-strip", "-quality", "{Q}", "{OUT}"}, "ImageMagick", nil
		case have("convert"):
			return []string{"convert", "{IN}", "-strip", "-quality", "{Q}", "{OUT}"}, "ImageMagick", nil
		case have("vips"):
			return []string{"vips", "copy", "{IN}", "{OUT}[Q={Q},strip]"}, "vips", nil
		}
		return nil, "", errors.New("no WebP encoder on this server: install ImageMagick (every distribution; from EPEL on the RHEL family), or the cwebp tool (libwebp-tools on RHEL 9, webp on Debian and Ubuntu)")
	case "avif":
		switch {
		case have("avifenc"):
			return []string{"avifenc", "-q", "{Q}", "--speed", "6", "{IN}", "{OUT}"}, "avifenc", nil
		case have("magick"):
			return []string{"magick", "{IN}", "-strip", "-quality", "{Q}", "{OUT}"}, "ImageMagick", nil
		case have("vips"):
			return []string{"vips", "copy", "{IN}", "{OUT}[Q={Q},strip]"}, "vips", nil
		}
		return nil, "", errors.New("no AVIF encoder on this server: install libavif-tools (RHEL family) or libavif-bin (Debian, Ubuntu), or an ImageMagick built with HEIF")
	}
	return nil, "", errors.New("format must be webp or avif")
}

// Op "images_convert": checks, then the job.
func imagesStart(raw json.RawMessage) (any, error) {
	var a imagesArgs
	json.Unmarshal(raw, &a)
	s, err := pickSite(a.Site)
	if err != nil {
		return nil, err
	}
	if s.Container != "" {
		return nil, errors.New("this site's files are inside a container; the conversion runs on the host and is not available for it yet")
	}
	if a.Format == "" {
		a.Format = "webp"
	}
	argv, toolName, err := imageTool(a.Format)
	if err != nil {
		return nil, err
	}
	_ = argv
	if a.Quality <= 0 {
		a.Quality = map[string]int{"webp": 82, "avif": 55}[a.Format]
	}
	if a.Quality > 100 {
		a.Quality = 100
	}
	if a.MaxFiles <= 0 || a.MaxFiles > imagesMaxFiles {
		a.MaxFiles = imagesMaxFiles
	}
	// The folders: the kind's upload folders by default, always inside the site.
	if len(a.Folders) == 0 {
		for _, u := range kindOf(s.Kind).Uploads {
			if isDir(filepath.Join(s.Root, u)) {
				a.Folders = append(a.Folders, u)
			}
		}
	}
	if len(a.Folders) == 0 {
		return nil, errors.New("no upload folder found for this site; pass folders (relative to the site root)")
	}
	var folders []string
	for _, f := range a.Folders {
		full := filepath.Clean(filepath.Join(s.Root, f))
		if !strings.HasPrefix(full+"/", filepath.Clean(s.Root)+"/") {
			return nil, fmt.Errorf("%s is outside the site", f)
		}
		if !isDir(full) {
			return nil, fmt.Errorf("%s is not a folder", f)
		}
		folders = append(folders, full)
	}
	a.Folders, a.Root, a.Owner, a.Tool, a.Site = folders, s.Root, s.Owner, toolName, ""
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(a)
	cmd := shellQuote(self) + " imgconvert " + base64.StdEncoding.EncodeToString(b)
	if privileged && s.Owner != "" && s.Owner != "root" {
		cmd = "runuser -u " + shellQuote(s.Owner) + " -- " + cmd
	}
	j, _ := json.Marshal(map[string]string{"command": cmd, "name": "convert_images " + filepath.Base(s.Root)})
	r, err := jobStart(j)
	if err != nil {
		return nil, err
	}
	m := r.(map[string]any)
	m["folders"], m["format"], m["quality"], m["encoder"], m["runs_as"] = folders, a.Format, a.Quality, toolName, s.Owner
	m["note"] = "Copies are written next to each original as <file>.webp (or .avif); originals are untouched; a copy that is not smaller is removed. Follow with job_output; the last line is the summary."
	if a.DryRun {
		m["note"] = "Dry run: counts the images that would be converted and their size, writes nothing."
	}
	return m, nil
}

var imageExt = map[string]bool{".jpg": true, ".jpeg": true, ".png": true}

// The job itself (sudowhizzy-agent imgconvert <base64 args>).
func imagesRun(b64 string) error {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	var a imagesArgs
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	argv, _, err := imageTool(a.Format)
	if err != nil {
		return err
	}
	ext := "." + a.Format
	started := time.Now()
	var converted, existing, noGain, failed, candidates int
	var before, after, candidateBytes int64
	stop := false
	for _, folder := range a.Folders {
		if stop {
			break
		}
		filepath.WalkDir(folder, func(path string, d os.DirEntry, err error) error {
			if err != nil || stop {
				return nil
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") || d.Name() == "cache" {
					return filepath.SkipDir
				}
				return nil
			}
			if !imageExt[strings.ToLower(filepath.Ext(path))] || strings.Contains(path, ".sw-part.") {
				return nil
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() || fi.Size() < imagesMinBytes || fi.Size() > imagesMaxBytes {
				return nil
			}
			out := path + ext
			if ofi, err := os.Stat(out); err == nil && !ofi.ModTime().Before(fi.ModTime()) {
				existing++
				return nil
			}
			candidates++
			candidateBytes += fi.Size()
			if a.DryRun {
				return nil
			}
			if candidates > a.MaxFiles || time.Since(started) > imagesTimeout {
				stop = true
				return filepath.SkipAll
			}
			// The encoders pick the format from the name, so the unfinished file keeps the extension.
			part := strings.TrimSuffix(out, ext) + ".sw-part" + ext
			args := make([]string, 0, len(argv))
			for _, x := range argv[1:] {
				x = strings.ReplaceAll(x, "{IN}", path)
				x = strings.ReplaceAll(x, "{OUT}", part)
				x = strings.ReplaceAll(x, "{Q}", fmt.Sprint(a.Quality))
				args = append(args, x)
			}
			cmd := exec.Command(argv[0], args...)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				failed++
				os.Remove(part)
				if failed <= 20 {
					fmt.Printf("failed: %s (%s)\n", path, strings.TrimSpace(strings.SplitN(stderr.String(), "\n", 2)[0]))
				}
				return nil
			}
			nfi, err := os.Stat(part)
			if err != nil || nfi.Size() == 0 || nfi.Size() >= fi.Size() {
				os.Remove(part)
				noGain++
				return nil
			}
			if err := os.Rename(part, out); err != nil {
				os.Remove(part)
				failed++
				return nil
			}
			converted++
			before += fi.Size()
			after += nfi.Size()
			if converted%100 == 0 {
				fmt.Printf("%d converted, %d MB -> %d MB so far\n", converted, before>>20, after>>20)
			}
			return nil
		})
	}
	if a.DryRun {
		fmt.Printf("dry run: %d images would be converted (%d MB), %d already have a %s copy\n", candidates, candidateBytes>>20, existing, a.Format)
		return nil
	}
	saved := 0
	if before > 0 {
		saved = int(100 - after*100/before)
	}
	summary, _ := json.Marshal(map[string]any{
		"converted": converted, "already_had_copy": existing, "no_gain": noGain, "failed": failed, "stopped_at_limit": stop,
		"mb_before": before >> 20, "mb_after": after >> 20, "saved_pct": saved, "seconds": int(time.Since(started).Seconds()),
	})
	fmt.Println(string(summary))
	return nil
}
