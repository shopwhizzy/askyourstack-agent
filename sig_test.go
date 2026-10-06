package main

import "testing"

// The scrambled patterns still match what they are meant to (and the binary holds none of these words).
func TestScrambledPatterns(t *testing.T) {
	php := map[string]bool{
		"<?php eval(base64_decode('aGk='));":         true,
		"<?php assert($_POST['x']);":                 true,
		"<?php $_GET['f']($_GET['a']);":              true,
		"<?php system($_REQUEST['c']);":              true,
		"<?php // Indo" + "Xploit shell":             true,
		"<?php echo 'hello world'; $a = strlen($b);": false,
	}
	for code, bad := range php {
		hit := false
		for _, p := range phpBad {
			hit = hit || p.re.MatchString(code)
		}
		if hit != bad {
			t.Errorf("%q: matched %v, want %v", code, hit, bad)
		}
		if bad && !phpTell.MatchString(code) {
			t.Errorf("%q: phpTell misses it", code)
		}
	}
	if !jsBad[3].re.MatchString(`var c = document.getElementById('cc_number').value; fetch('https://x')`) {
		t.Error("card skimmer not matched")
	}
}
