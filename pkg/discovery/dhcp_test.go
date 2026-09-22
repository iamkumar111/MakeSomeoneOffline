package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLeaseFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseDNSMasqLeasesSkipsExpired(t *testing.T) {
	now := time.Now().UTC()

	// Expiry 0 (infinite) and unparsable expiry are treated as valid.
	path := writeLeaseFile(t,
		"0 aa:bb:cc:dd:ee:01 192.168.1.101 infinite-phone *\n"+
			"notanumber aa:bb:cc:dd:ee:02 192.168.1.102 bad-expiry *\n")
	leases := parseDNSMasqLeasesAt(path, now)
	if len(leases) != 2 {
		t.Fatalf("expected 2 valid leases, got %d: %+v", len(leases), leases)
	}

	// Long-past epoch must be skipped (departed device).
	expired := parseDNSMasqLeasesAt(writeLeaseFile(t,
		"1000000000 aa:bb:cc:dd:ee:03 192.168.1.103 old-phone *\n"), now)
	if len(expired) != 0 {
		t.Fatalf("expected expired lease to be skipped, got %+v", expired)
	}

	// Far-future epoch is kept with hostname and parsed expiry.
	fresh := parseDNSMasqLeasesAt(writeLeaseFile(t,
		"9999999999 aa:bb:cc:dd:ee:04 192.168.1.104 new-phone *\n"), now)
	if len(fresh) != 1 || fresh[0].Hostname != "new-phone" {
		t.Fatalf("expected 1 fresh lease, got %+v", fresh)
	}
	if fresh[0].Expiry.IsZero() {
		t.Fatal("expected expiry to be parsed")
	}
}
