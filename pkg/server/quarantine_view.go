package server

import "github.com/open-netcut/open-netcut/pkg/models"

func liveQuarantineIDs(enforcements []*models.Enforcement) map[string]bool {
	ids := make(map[string]bool)
	for _, e := range enforcements {
		if e.Action == models.ActionQuarantine && e.ActualState == models.StateApplied && !e.DryRun {
			ids[e.DeviceID] = true
		}
	}
	return ids
}

// Project status without changing discovery's administrative trust decisions.
func quarantineView(device *models.Device, ids map[string]bool) *models.Device {
	copy := *device
	if ids[device.ID] {
		copy.TrustState = models.TrustStateQuarantined
	} else if copy.TrustState == models.TrustStateQuarantined {
		copy.TrustState = models.TrustStateUnknown
	}
	return &copy
}
