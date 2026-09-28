package traffic

import (
	"testing"
)

func TestSplitAcctComment(t *testing.T) {
	dir, ip := splitAcctComment(`"netcut-acct-saddr-192.168.1.10"`)
	if dir != "saddr" || ip != "192.168.1.10" {
		t.Fatalf("got %q %q", dir, ip)
	}
	dir, ip = splitAcctComment("netcut-acct-daddr-10.0.0.5")
	if dir != "daddr" || ip != "10.0.0.5" {
		t.Fatalf("got %q %q", dir, ip)
	}
	if dir, ip := splitAcctComment("something-else"); dir != "" || ip != "" {
		t.Fatalf("expected empty, got %q %q", dir, ip)
	}
}

func TestParseNftJSON(t *testing.T) {
	raw := []byte(`{"nftables": [
		{"metainfo": {"version": "1.0"}},
		{"rule": {"comment": "netcut-acct-saddr-192.168.1.10", "expr": [{"match": {}}, {"counter": {"packets": 5, "bytes": 800}}]}},
		{"rule": {"comment": "netcut-acct-daddr-192.168.1.10", "expr": [{"counter": {"packets": 3, "bytes": 1200}}]}},
		{"rule": {"comment": "unrelated", "expr": [{"counter": {"packets": 9, "bytes": 99999}}]}}
	]}`)
	rx, tx := parseNftJSON(raw)
	if rx["192.168.1.10"] != 1200 {
		t.Fatalf("rx = %v", rx)
	}
	if tx["192.168.1.10"] != 800 {
		t.Fatalf("tx = %v", tx)
	}
	if len(rx)+len(tx) != 2 {
		t.Fatalf("unrelated rule leaked: rx=%v tx=%v", rx, tx)
	}
}

func TestParseNftText(t *testing.T) {
	raw := "table inet open_netcut {\n" +
		"\tchain accounting_fwd {\n" +
		"\t\tip saddr 192.168.1.10 counter packets 5 bytes 400 accept comment \"netcut-acct-saddr-192.168.1.10\"\n" +
		"\t\tip daddr 192.168.1.10 counter packets 3 bytes 1200 accept comment \"netcut-acct-daddr-192.168.1.10\"\n" +
		"\t}\n}\n"
	rx, tx := parseNftText(raw)
	if tx["192.168.1.10"] != 400 {
		t.Fatalf("tx = %v", tx)
	}
	if rx["192.168.1.10"] != 1200 {
		t.Fatalf("rx = %v", rx)
	}
}

func TestDeltaUpdate(t *testing.T) {
	last := map[string]uint64{}
	if d := deltaUpdate(last, "1.2.3.4", 100); d != 0 {
		t.Fatalf("first sight should rebase, got %d", d)
	}
	if d := deltaUpdate(last, "1.2.3.4", 150); d != 50 {
		t.Fatalf("got %d", d)
	}
	if d := deltaUpdate(last, "1.2.3.4", 10); d != 0 {
		t.Fatalf("reset should rebase, got %d", d)
	}
	if d := deltaUpdate(last, "1.2.3.4", 30); d != 20 {
		t.Fatalf("got %d", d)
	}
}
