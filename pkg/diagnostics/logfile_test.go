package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogRetainsPreviousRunAndRotates(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenLog(dir, 12, 2)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("old-run\n"))
	w.Close()
	w, err = OpenLog(dir, 12, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, line := range []string{"new-run\n", "third\n", "fourth\n"} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(filepath.Join(dir, "control-plane.log.2"))
	if err != nil || !strings.Contains(string(old), "new-run") {
		t.Fatalf("history: %q %v", old, err)
	}
	current, err := os.ReadFile(filepath.Join(dir, "control-plane.log"))
	if err != nil || string(current) != "fourth\n" {
		t.Fatalf("current: %q %v", current, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "control-plane.log.3")); !os.IsNotExist(err) {
		t.Fatal("retention exceeded")
	}
}
