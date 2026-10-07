package adapters

import (
	"fmt"
	"strconv"
	"strings"
)

// An unrecognized registry result must not turn a failed safety check into
// permission to enforce. Only a parsed zero confirms forwarding is disabled.
func parseIPEnableRouter(output string) (bool, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "IPEnableRouter") {
			continue
		}
		if len(fields) != 3 || !strings.EqualFold(fields[1], "REG_DWORD") {
			return false, fmt.Errorf("cannot verify IP forwarding state: unexpected IPEnableRouter format")
		}
		value, err := strconv.ParseUint(fields[2], 0, 32)
		if err != nil {
			return false, fmt.Errorf("cannot verify IP forwarding state: invalid IPEnableRouter value %q", fields[2])
		}
		return value != 0, nil
	}
	return false, fmt.Errorf("cannot verify IP forwarding state: IPEnableRouter missing from registry output")
}
