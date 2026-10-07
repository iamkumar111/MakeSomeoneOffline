package adapters

import "testing"

func TestParseIPEnableRouter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		output  string
		enabled bool
		wantErr bool
	}{
		{"off", "HKEY_LOCAL_MACHINE\\...\r\n    IPEnableRouter    REG_DWORD    0x0\r\n", false, false},
		{"on", "    IPEnableRouter    REG_DWORD    0x1", true, false},
		{"nonzero", "IPEnableRouter REG_DWORD 0x2", true, false},
		{"missing", "HKEY_LOCAL_MACHINE\\...", false, true},
		{"invalid", "IPEnableRouter REG_DWORD nonsense", false, true},
		{"wrong type", "IPEnableRouter REG_SZ 0", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, err := parseIPEnableRouter(tc.output)
			if enabled != tc.enabled || (err != nil) != tc.wantErr {
				t.Fatalf("enabled=%v error=%v", enabled, err)
			}
		})
	}
}
