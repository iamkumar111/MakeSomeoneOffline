//go:build !darwin

package adapters

import (
	"context"
	"fmt"
)

func MacOSProbe(context.Context, string) (MacOSProbeResult, error) {
	err := fmt.Errorf("mac-tool probe requires macOS")
	return MacOSProbeResult{Blockers: []string{err.Error()}}, err
}
