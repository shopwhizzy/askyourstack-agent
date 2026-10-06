package main

import "testing"

func TestRsyncSenderCheck(t *testing.T) {
	root := "/var/www/shop"
	ok := []string{
		`rsync --server --sender -logDtpre.iLsfxCIvu --numeric-ids . /var/www/shop/`,
		`rsync --server --sender -logDtprHe.iLsfxCIvu --numeric-ids --delete . /var/www/shop/pub/media/`,
		`rsync --server --sender -vlogDtprze.iLsfxCIvu . /var/www/shop/my\ folder/`,
	}
	bad := []string{
		`rsync --server -logDtpre.iLsfxCIvu . /var/www/shop/`,                                // receiving: would write here
		`rsync --server --sender -logDtpre.iLsfxCIvu . /etc/`,                                // outside the folder
		`rsync --server --sender -logDtpre.iLsfxCIvu . /var/www/shop/../../etc`,              // escapes
		`rsync --server --sender -logDtpre.iLsfxCIvu . /var/www/shopx`,                       // prefix trick
		`rsync --server --sender -LogDtpre.iLsfxCIvu . /var/www/shop/`,                       // follows symlinks out
		`rsync --server --sender --remove-source-files -logDtpre.iLsfxCIvu . /var/www/shop/`, // deletes the source
		`rsync --server --sender --files-from=/etc/shadow -logDtpre.iLsfxCIvu . /var/www/shop/`,
		`sh -c reboot`,
		`rsync --server --sender -logDtpre.iLsfxCIvu . /var/www/shop/; reboot`,
		``,
	}
	for _, c := range ok {
		if err := checkRsyncSender(splitRsyncArgs(c), root); err != nil {
			t.Errorf("should allow %q: %v", c, err)
		}
	}
	for _, c := range bad {
		if err := checkRsyncSender(splitRsyncArgs(c), root); err == nil {
			t.Errorf("should refuse %q", c)
		}
	}
}
