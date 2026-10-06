package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSoftware(t *testing.T) {
	d := t.TempDir()
	mk(t, d, map[string]string{
		"wp-content/plugins/contact-form-7/wp-contact-form-7.php": "<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.9.8\n*/\n",
		"wp-content/plugins/contact-form-7/helper.php":            "<?php // Version: 9.9.9 is not a plugin header\n",
		"wp-content/plugins/hello.php":                            "<?php\n/**\n * Plugin Name: Hello Dolly\n * Version: 1.7.2\n */\n",
		"wp-content/plugins/broken/x.php":                         "<?php echo 1;\n",
		"wp-content/themes/astra/style.css":                       "/*\nTheme Name: Astra\nVersion: 4.8.3\n*/\n",
		"wp-content/themes/notes/readme.txt":                      "no theme here",
		"composer.lock":                                           `{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.4.0"}, {"name": "magento/framework", "version": "v103.0.6"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}`,
	})
	p := wpPlugins(d)
	if len(p) != 2 || p[0].Slug != "contact-form-7" || p[0].Version != "5.9.8" || p[1].Slug != "hello" || p[1].Version != "1.7.2" {
		t.Fatalf("plugins: %+v", p)
	}
	if th := wpThemes(d); len(th) != 1 || th[0].Slug != "astra" || th[0].Version != "4.8.3" {
		t.Fatalf("themes: %+v", th)
	}
	if c := composerPackages(d); len(c) != 2 || c[1].Slug != "magento/framework" || c[1].Version != "103.0.6" {
		t.Fatalf("packages: %+v", c)
	}
	os.Remove(filepath.Join(d, "composer.lock"))
	if c := composerPackages(d); c != nil {
		t.Fatalf("no lock: %+v", c)
	}
}
