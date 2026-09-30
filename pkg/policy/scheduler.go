package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// PolicySchedule defines an active recurring time window.
type PolicySchedule struct {
	ID        string           `json:"id"`
	PolicyID  string           `json:"policy_id"`
	DeviceID  string           `json:"device_id"`
	Days      []time.Weekday   `json:"days"`       // e.g. Mon, Tue, Wed...
	StartHour int              `json:"start_hour"` // 0-23
	StartMin  int              `json:"start_min"`  // 0-59
	EndHour   int              `json:"end_hour"`   // 0-23
	EndMin    int              `json:"end_min"`    // 0-59
	Action    models.PolicyActionType `json:"action"`
	Adapter   string           `json:"adapter,omitempty"`    // "" = engine default
	TTLSeconds int             `json:"ttl_seconds,omitempty"` // 0 = window end lifts it
	DownloadBps uint64         `json:"download_bps,omitempty"`
	UploadBps   uint64         `json:"upload_bps,omitempty"`
	Active    bool             `json:"active"`
	enforcedID string          // ID of currently active enforcement if inside window
}

// ScheduleManager handles cron-like time-window based policy activations.
type ScheduleManager struct {
	mu           sync.RWMutex
	schedules    map[string]*PolicySchedule
	policyEngine *PolicyEngine
	resolve      func(deviceID string) *models.Device
	stopCh       chan struct{}
}

// NewScheduleManager creates an instance of ScheduleManager.
func NewScheduleManager(pe *PolicyEngine) *ScheduleManager {
	sm := &ScheduleManager{
		schedules:    make(map[string]*PolicySchedule),
		policyEngine: pe,
		stopCh:       make(chan struct{}),
	}

	go sm.schedulerLoop()
	return sm
}

// SetResolver installs the device lookup used at fire time. Without it,
// scheduled enforcements cannot resolve targets and are skipped.
func (sm *ScheduleManager) SetResolver(resolve func(deviceID string) *models.Device) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.resolve = resolve
}

// ListSchedules returns copies of all schedules.
func (sm *ScheduleManager) ListSchedules() []*PolicySchedule {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]*PolicySchedule, 0, len(sm.schedules))
	for _, s := range sm.schedules {
		cp := *s
		out = append(out, &cp)
	}
	return out
}

// AddSchedule adds or updates a scheduled policy.
func (sm *ScheduleManager) AddSchedule(sched *PolicySchedule) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.schedules[sched.ID] = sched
}

// RemoveSchedule removes a scheduled rule and rolls back any current enforcement.
func (sm *ScheduleManager) RemoveSchedule(id string) {
	sm.mu.Lock()
	sched, ok := sm.schedules[id]
	if ok && sched.enforcedID != "" {
		enfID, action := sched.enforcedID, sched.Action
		sm.mu.Unlock()
		if action == models.ActionRateLimit {
			_ = sm.policyEngine.RemoveRateLimit(context.Background(), enfID, "schedule_removed")
		} else {
			_ = sm.policyEngine.RemoveQuarantine(context.Background(), enfID, "schedule_removed")
		}
		sm.mu.Lock()
	}
	delete(sm.schedules, id)
	sm.mu.Unlock()
}

// IsInsideWindow determines if a given timestamp falls within the schedule window.
func (sm *ScheduleManager) IsInsideWindow(sched *PolicySchedule, t time.Time) bool {
	// Check weekday
	dayMatch := false
	if len(sched.Days) == 0 {
		dayMatch = true
	} else {
		for _, d := range sched.Days {
			if t.Weekday() == d {
				dayMatch = true
				break
			}
		}
	}
	if !dayMatch {
		return false
	}

	currentMinutes := t.Hour()*60 + t.Minute()
	startMinutes := sched.StartHour*60 + sched.StartMin
	endMinutes := sched.EndHour*60 + sched.EndMin

	if startMinutes <= endMinutes {
		return currentMinutes >= startMinutes && currentMinutes < endMinutes
	}
	// Overnight window (e.g. 22:00 to 06:00)
	return currentMinutes >= startMinutes || currentMinutes < endMinutes
}

func (sm *ScheduleManager) schedulerLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return
		case now := <-ticker.C:
			sm.evaluateSchedules(now)
		}
	}
}

func (sm *ScheduleManager) evaluateSchedules(now time.Time) {
	// Snapshot under read lock; enforcement calls out to adapters and must
	// never run while holding the schedule lock.
	sm.mu.RLock()
	snap := make([]*PolicySchedule, 0, len(sm.schedules))
	for _, s := range sm.schedules {
		cp := *s
		snap = append(snap, &cp)
	}
	resolve := sm.resolve
	sm.mu.RUnlock()

	for _, sched := range snap {
		if !sched.Active {
			continue
		}
		inside := sm.IsInsideWindow(sched, now)

		sm.mu.RLock()
		cur, ok := sm.schedules[sched.ID]
		var enforcedID string
		if ok {
			enforcedID = cur.enforcedID
		}
		sm.mu.RUnlock()
		if !ok {
			continue // deleted concurrently
		}

		if inside && enforcedID == "" {
			// Window opened -> resolve the live device and enforce.
			// A bare ID is not enough: adapters need IP/MAC targets.
			dev := resolveDevice(resolve, sched.DeviceID)
			if dev == nil {
				continue
			}
			actor := fmt.Sprintf("schedule:%s", sched.ID)
			ttl := time.Duration(sched.TTLSeconds) * time.Second
			var enfID string
			if sched.Action == models.ActionRateLimit {
				enf, err := sm.policyEngine.ApplyRateLimit(context.Background(), dev, sched.Adapter, sched.DownloadBps, sched.UploadBps, ttl, actor, false)
				if err == nil && enf != nil {
					enfID = enf.ID
				}
			} else {
				// Empty adapter = engine safe default (never l2_arp).
				enf, err := sm.policyEngine.ApplyQuarantine(context.Background(), dev, sched.Adapter, ttl, actor, false)
				if err == nil && enf != nil {
					enfID = enf.ID
				}
			}
			sm.mu.Lock()
			if s, ok := sm.schedules[sched.ID]; ok && s.enforcedID == "" {
				s.enforcedID = enfID
			}
			sm.mu.Unlock()
		} else if !inside && enforcedID != "" {
			// Window closed -> lift enforcement with the matching remover.
			if sched.Action == models.ActionRateLimit {
				_ = sm.policyEngine.RemoveRateLimit(context.Background(), enforcedID, fmt.Sprintf("schedule_end:%s", sched.ID))
			} else {
				_ = sm.policyEngine.RemoveQuarantine(context.Background(), enforcedID, fmt.Sprintf("schedule_end:%s", sched.ID))
			}
			sm.mu.Lock()
			if s, ok := sm.schedules[sched.ID]; ok {
				s.enforcedID = ""
			}
			sm.mu.Unlock()
		}
	}
}

// resolveDevice looks up a live device; nil when no resolver or unknown ID.
func resolveDevice(resolve func(deviceID string) *models.Device, id string) *models.Device {
	if resolve == nil || id == "" {
		return nil
	}
	return resolve(id)
}

// Stop cleanly terminates the scheduler loop.
func (sm *ScheduleManager) Stop() {
	close(sm.stopCh)
}
