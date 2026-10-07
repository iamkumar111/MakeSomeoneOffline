package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/detection"
	"github.com/open-netcut/open-netcut/pkg/discovery"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
	"github.com/open-netcut/open-netcut/pkg/notify"
	"github.com/open-netcut/open-netcut/pkg/policy"
	"github.com/open-netcut/open-netcut/pkg/store"
	"github.com/open-netcut/open-netcut/pkg/traffic"
)

// Server coordinates HTTP API, WebSocket broadcasting, and domain engines.
type Server struct {
	fusionEngine    *discovery.IdentityFusionEngine
	detectionEngine *detection.DetectionEngine
	policyEngine    *policy.PolicyEngine
	telemetryEngine *traffic.TelemetryEngine
	eventBus        *events.EventBus
	store           store.Store
	sched           *policy.ScheduleManager
	autoRem         *policy.AutoRemediationEngine
	dispatcher      *notify.AlertDispatcher
	freeze          *policy.FreezeController
	router          *http.ServeMux
	siteID          string
	actionMu        sync.Mutex
	actionBusy      bool
}

// ServerOption wires optional engines without breaking existing callers.
type ServerOption func(*Server)

// WithScheduler enables the /schedules API.
func WithScheduler(sm *policy.ScheduleManager) ServerOption {
	return func(s *Server) { s.sched = sm }
}

// WithAutoRemediation enables the /remediation API.
func WithAutoRemediation(ar *policy.AutoRemediationEngine) ServerOption {
	return func(s *Server) { s.autoRem = ar }
}

// WithAlertDispatcher enables the /webhooks API.
func WithAlertDispatcher(ad *notify.AlertDispatcher) ServerOption {
	return func(s *Server) { s.dispatcher = ad }
}

// WithFreezeController enables latch-backed /freeze (newcomers auto-cut).
func WithFreezeController(fc *policy.FreezeController) ServerOption {
	return func(s *Server) { s.freeze = fc }
}

// NewServer builds and wires the control plane HTTP API.
// (The old topology engine was removed with the UI topology page.)
func NewServer(
	fusion *discovery.IdentityFusionEngine,
	det *detection.DetectionEngine,
	pol *policy.PolicyEngine,
	telem *traffic.TelemetryEngine,
	bus *events.EventBus,
	st store.Store,
	siteID string,
	opts ...ServerOption,
) *Server {
	s := &Server{
		fusionEngine:    fusion,
		detectionEngine: det,
		policyEngine:    pol,
		telemetryEngine: telem,
		eventBus:        bus,
		store:           st,
		router:          http.NewServeMux(),
		siteID:          siteID,
	}
	for _, opt := range opts {
		opt(s)
	}

	s.routes()
	return s
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return requestLogging(s.secureHandler(s.router))
}

func (s *Server) routes() {
	s.router.HandleFunc("/api/v1/stats", s.enableCORS(s.handleStats))
	s.router.HandleFunc("/api/v1/sites", s.enableCORS(s.handleSites))
	s.router.HandleFunc("/api/v1/devices", s.enableCORS(s.handleDevices))
	s.router.HandleFunc("/api/v1/devices/", s.enableCORS(s.handleDeviceDetail))
	s.router.HandleFunc("/api/v1/alerts", s.enableCORS(s.handleAlerts))
	s.router.HandleFunc("/api/v1/alerts/", s.enableCORS(s.handleAlertAck))
	s.router.HandleFunc("/api/v1/enforcements", s.enableCORS(s.handleEnforcements))
	s.router.HandleFunc("/api/v1/freeze", s.enableCORS(s.handleFreeze))
	s.router.HandleFunc("/api/v1/whoami", s.enableCORS(s.handleWhoAmI))
	s.router.HandleFunc("/api/v1/allowlist", s.enableCORS(s.handleAllowlist))
	s.router.HandleFunc("/api/v1/audit", s.enableCORS(s.handleAuditLogs))
	s.router.HandleFunc("/api/v1/traffic", s.enableCORS(s.handleTraffic))
	s.router.HandleFunc("/api/v1/observations", s.enableCORS(s.handleObservations))
	s.router.HandleFunc("/api/v1/remediation", s.enableCORS(s.handleRemediation))
	s.router.HandleFunc("/api/v1/policies", s.enableCORS(s.handlePolicies))
	s.router.HandleFunc("/api/v1/policies/", s.enableCORS(s.handlePolicyDetail))
	s.router.HandleFunc("/api/v1/integrations", s.enableCORS(s.handleIntegrations))
	s.router.HandleFunc("/api/v1/integrations/", s.enableCORS(s.handleIntegrationDetail))
	s.router.HandleFunc("/api/v1/schedules", s.enableCORS(s.handleSchedules))
	s.router.HandleFunc("/api/v1/schedules/", s.enableCORS(s.handleScheduleDetail))
	s.router.HandleFunc("/api/v1/webhooks", s.enableCORS(s.handleWebhooks))
	s.router.HandleFunc("/api/v1/webhooks/", s.enableCORS(s.handleWebhookDetail))
	s.router.HandleFunc("/api/v1/cameras", s.enableCORS(s.handleCameras))
	s.router.HandleFunc("/api/v1/cameras/", s.enableCORS(s.handleCameraDetail))
	s.router.HandleFunc("/api/v1/export/devices.csv", s.enableCORS(s.handleExportDevicesCSV))
	s.router.HandleFunc("/api/v1/export/audit.csv", s.enableCORS(s.handleExportAuditCSV))
	s.router.HandleFunc("/api/v1/events", s.handleWebSocket)
	s.router.HandleFunc("/api/v1/events/sse", s.handleSSE)

	// Serve built frontend assets if directory exists
	fs := http.FileServer(http.Dir("./web/dist"))
	s.router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	}))
}

func (s *Server) allowedOrigin() string {
	if v := os.Getenv("ALLOWED_ORIGIN"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

func (s *Server) enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allow := s.allowedOrigin()
		// Reflect localhost dev origins; otherwise use configured origin (never "*"
		// with credentials). Same-origin requests (no Origin header) are allowed.
		if origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", allow)
		} else if s.validOrigin(r) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", allow)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User, X-Actor")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// actorFromRequest replaces hardcoded "api_user"/"admin" with caller identity.
func actorFromRequest(r *http.Request) string {
	for _, h := range []string{"X-Actor", "X-User", "X-Forwarded-User"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		return u
	}
	if q := strings.TrimSpace(r.URL.Query().Get("actor")); q != "" {
		return q
	}
	return "api_user"
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices := s.fusionEngine.ListDevices()
	seen := map[string]int{}
	for _, d := range devices {
		site := d.SiteID
		if site == "" {
			site = s.siteID
		}
		seen[site]++
	}
	type siteInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DeviceCount int    `json:"device_count"`
	}
	list := []siteInfo{{ID: s.siteID, Name: s.siteID}}
	if _, ok := seen[s.siteID]; !ok {
		seen[s.siteID] = 0
	}
	for id, n := range seen {
		found := false
		for i := range list {
			if list[i].ID == id {
				list[i].DeviceCount = n
				found = true
			}
		}
		if !found {
			list = append(list, siteInfo{ID: id, Name: id, DeviceCount: n})
		}
	}
	for i := range list {
		if n, ok := seen[list[i].ID]; ok {
			list[i].DeviceCount = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	devices := s.fusionEngine.ListDevices()
	alerts := s.detectionEngine.ListAlerts()
	enforcements := s.policyEngine.ListEnforcements()

	onlineCount := 0
	quarantinedCount := len(liveQuarantineIDs(enforcements))
	for _, d := range devices {
		if d.IsOnline {
			onlineCount++
		}
	}

	criticalAlerts := 0
	for _, a := range alerts {
		if !a.Acknowledged && (a.Severity == models.SeverityCritical || a.Severity == models.SeverityHigh) {
			criticalAlerts++
		}
	}

	resp := map[string]interface{}{
		"total_devices":       len(devices),
		"online_devices":      onlineCount,
		"quarantined_devices": quarantinedCount,
		"active_enforcements": len(enforcements),
		"active_alerts":       len(alerts),
		"critical_alerts":     criticalAlerts,
		"timestamp":           time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	devices := s.fusionEngine.ListDevices()
	ids := liveQuarantineIDs(s.policyEngine.ListEnforcements())
	for i, device := range devices {
		devices[i] = quarantineView(device, ids)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(devices)
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"), "/")
	deviceID := parts[0]
	if deviceID == "" {
		http.Error(w, "Device ID required", http.StatusBadRequest)
		return
	}

	dev, ok := s.fusionEngine.GetDevice(deviceID)
	if !ok {
		// Fall back to MAC lookup so operators can use
		// /devices/00:e0:27:2e:b1:b3/... directly.
		dev, ok = s.fusionEngine.GetDeviceByMAC(deviceID)
	}
	if !ok {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if len(parts) > 1 {
		action := parts[1]
		actor := actorFromRequest(r)
		switch action {
		case "quarantine":
			if r.Method == http.MethodPost {
				var req struct {
					Adapter    string `json:"adapter"`
					TTLSec     int    `json:"ttl_seconds"`
					DryRun     bool   `json:"dry_run"`
					BreakGlass bool   `json:"break_glass"`
					Reason     string `json:"reason"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid quarantine request JSON", http.StatusBadRequest)
					return
				}
				if req.TTLSec < 0 || req.TTLSec > 30*24*60*60 {
					http.Error(w, "ttl_seconds must be between 0 and 2592000 (30 days)", http.StatusBadRequest)
					return
				}
				ttl := time.Duration(req.TTLSec) * time.Second
				if ttl == 0 {
					ttl = 15 * time.Minute // safe default TTL
				}

				// Idempotent re-cut: a live enforcement already covers this
				// device (e.g. double-click, retry after timeout). Return it
				// instead of stacking a duplicate poison loop.
				if !req.DryRun {
					for _, e := range s.policyEngine.ListEnforcements() {
						if e.DeviceID == dev.ID && e.Action == models.ActionQuarantine && e.ActualState == models.StateApplied && !e.DryRun {
							w.Header().Set("Content-Type", "application/json")
							_ = json.NewEncoder(w).Encode(map[string]interface{}{
								"status": "already_cut", "enforcement": e,
							})
							return
						}
					}
				}

				var enf *models.Enforcement
				var err error
				if req.BreakGlass {
					// Explicit allowlist override for protected infrastructure.
					// Automated paths can never reach this (no reason = rejected).
					enf, err = s.policyEngine.ApplyQuarantineBreakGlass(r.Context(), dev, req.Adapter, ttl, actor, req.DryRun, req.Reason)
				} else {
					enf, err = s.policyEngine.ApplyQuarantine(r.Context(), dev, req.Adapter, ttl, actor, req.DryRun)
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(enf)
				return
			} else if r.Method == http.MethodDelete {
				enfs := s.policyEngine.ListEnforcements()
				failures := 0
				var releaseErrors []string
				for _, e := range enfs {
					if e.DeviceID == dev.ID && e.Action == models.ActionQuarantine {
						if err := s.policyEngine.RemoveQuarantine(r.Context(), e.ID, actor); err != nil {
							failures++
							releaseErrors = append(releaseErrors, err.Error())
						}
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if failures > 0 {
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "release incomplete", "remove_failures": failures, "errors": releaseErrors})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "quarantine removed", "remove_failures": 0})
				return
			}
		case "trust":
			// Operator trust assignment: trusted | restricted | unknown.
			// Quarantined is managed via quarantine endpoints, not here.
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				var req struct {
					State models.TrustState `json:"state"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				switch req.State {
				case models.TrustStateTrusted, models.TrustStateRestricted, models.TrustStateUnknown:
					if err := s.fusionEngine.SetTrustState(dev.ID, req.State); err != nil {
						http.Error(w, err.Error(), http.StatusNotFound)
						return
					}
					s.policyEngine.Audit(actor, "trust_set", "device", dev.ID, fmt.Sprintf("trust=%s", req.State), "success")
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "trust updated", "state": string(req.State)})
					return
				default:
					http.Error(w, "state must be trusted, restricted or unknown", http.StatusBadRequest)
					return
				}
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		case "rename": // Manual operator rename (rank 5, beats all automatic sources).
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				var req struct {
					Name string `json:"name"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if err := s.fusionEngine.SetCustomName(dev.ID, req.Name); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "renamed", "name": strings.TrimSpace(req.Name)})
				return
			} else if r.Method == http.MethodDelete {
				if err := s.fusionEngine.ClearCustomName(dev.ID); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "rename cleared"})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		case "rate-limit":
			if r.Method == http.MethodPut || r.Method == http.MethodPost {
				var req struct {
					Adapter     string `json:"adapter"`
					DownloadBps uint64 `json:"download_bps"`
					UploadBps   uint64 `json:"upload_bps"`
					TTLSec      int    `json:"ttl_seconds"`
					DryRun      bool   `json:"dry_run"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				ttl := time.Duration(req.TTLSec) * time.Second
				if ttl == 0 {
					ttl = 15 * time.Minute
				}

				enf, err := s.policyEngine.ApplyRateLimit(r.Context(), dev, req.Adapter, req.DownloadBps, req.UploadBps, ttl, actor, req.DryRun)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(enf)
				return
			} else if r.Method == http.MethodDelete {
				enfs := s.policyEngine.ListEnforcements()
				for _, e := range enfs {
					if e.DeviceID == dev.ID && e.Action == models.ActionRateLimit {
						_ = s.policyEngine.RemoveRateLimit(r.Context(), e.ID, actor)
					}
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "rate limit removed"})
				return
			}
		case "traffic":
			if r.Method == http.MethodGet {
				stats, ok := s.telemetryEngine.GetDeviceStats(dev.ID)
				if !ok {
					// Return zeroed stats rather than 404 so UI can render sparklines.
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"device_id": dev.ID, "rx_bytes": 0, "tx_bytes": 0,
						"rx_rate_bps": 0, "tx_rate_bps": 0,
					})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(stats)
				return
			}
		case "observations":
			if r.Method == http.MethodGet {
				hist := s.fusionEngine.GetObservationHistory(dev.ID, 100)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(hist)
				return
			}
		}
	}

	dev = quarantineView(dev, liveQuarantineIDs(s.policyEngine.ListEnforcements()))
	// Enriched detail: device + live traffic + enforcements + related alerts.
	if r.URL.Query().Get("enriched") == "true" {
		stats, _ := s.telemetryEngine.GetDeviceStats(dev.ID)
		hist := s.fusionEngine.GetObservationHistory(dev.ID, 50)
		var devEnfs []*models.Enforcement
		for _, e := range s.policyEngine.ListEnforcements() {
			if e.DeviceID == dev.ID {
				devEnfs = append(devEnfs, e)
			}
		}
		var devAlerts []*models.Alert
		for _, a := range s.detectionEngine.ListAlerts() {
			if a.DeviceID == dev.ID || a.TargetMAC == dev.PrimaryMAC || a.TargetIP == dev.PrimaryIP {
				devAlerts = append(devAlerts, a)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device": dev, "traffic": stats, "observations": hist,
			"enforcements": devEnfs, "alerts": devAlerts,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dev)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	alerts := s.detectionEngine.ListAlerts()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(alerts)
}

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/"), "/")
	alertID := parts[0]
	if alertID == "" {
		http.Error(w, "Alert ID required", http.StatusBadRequest)
		return
	}

	if len(parts) > 1 && parts[1] == "ack" && r.Method == http.MethodPost {
		if err := s.detectionEngine.AcknowledgeAlert(r.Context(), alertID, actorFromRequest(r)); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *Server) handleEnforcements(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list := s.policyEngine.ListEnforcements()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleWhoAmI reports how the server sees the caller (their LAN IP), so the
// UI can offer "keep MY internet working" during a freeze.
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	resp := map[string]interface{}{"ip": ip}
	if ip != "" {
		if dev, ok := s.findDeviceByIP(ip); ok {
			resp["device_id"] = dev.ID
			resp["display_name"] = dev.DisplayName
			resp["mac"] = dev.PrimaryMAC
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// clientIP extracts the caller's IP from the direct TCP peer. On a LAN this
// is the admin's device address (no proxies involved).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return strings.TrimSpace(host)
}

func (s *Server) findDeviceByIP(ip string) (*models.Device, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, false
	}
	for _, dev := range s.fusionEngine.ListDevices() {
		if strings.TrimSpace(dev.PrimaryIP) == ip {
			return dev, true
		}
	}
	return nil, false
}

// handleFreeze cuts or restores whole-LAN internet at once, as a LATCH:
// while active, devices joining later are cut automatically too.
// Cutting ONLY the gateway device does not stop LAN clients (their ARP caches
// are untouched), so Freeze quarantines every online, non-allowlisted device.
// POST and DELETE run the bulk work in the background and answer 202
// immediately: cutting ~25 devices one by one outlasts HTTP timeouts, so a
// synchronous response would hang the UI. Progress is observable via
// /enforcements, /freeze (GET) and the audit trail.
// POST {adapter, ttl_seconds, reason, dry_run, include_self} / DELETE (lifts
// everything, including manual cuts) / GET (latch status).
func (s *Server) tryAction() bool {
	s.actionMu.Lock()
	defer s.actionMu.Unlock()
	if s.actionBusy {
		return false
	}
	s.actionBusy = true
	return true
}

func (s *Server) actionDone() {
	s.actionMu.Lock()
	s.actionBusy = false
	s.actionMu.Unlock()
}

func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	if s.freeze == nil {
		http.Error(w, "freeze controller not configured", http.StatusServiceUnavailable)
		return
	}
	actor := actorFromRequest(r)
	if r.Method == http.MethodGet {
		snap := s.freeze.Snapshot()
		activeCuts := 0
		for _, e := range s.policyEngine.ListEnforcements() {
			if e.Action == models.ActionQuarantine && e.ActualState == models.StateApplied && !e.DryRun {
				activeCuts++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": snap.Active, "adapter": snap.Adapter,
			"ttl_seconds": snap.TTLSeconds, "reason": snap.Reason,
			"exclude_self": snap.ExcludeSelf, "self_ip": snap.SelfIP,
			"active_cuts": activeCuts,
		})
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			Adapter     string `json:"adapter"`
			TTLSec      int    `json:"ttl_seconds"`
			Reason      string `json:"reason"`
			DryRun      bool   `json:"dry_run"`
			IncludeSelf bool   `json:"include_self"`
			SelfIP      string `json:"self_ip"`
			SelfMAC     string `json:"self_mac"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.TrimSpace(req.Reason) == "" {
			http.Error(w, "a reason is required to freeze the whole LAN", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSec) * time.Second
		// Resolve the operator's own device. Explicit self_ip/self_mac from
		// the UI wins; otherwise the connection peer is used. NOTE: when the
		// dashboard is opened via localhost, the peer is 127.0.0.1/::1 and
		// matches no LAN device — the UI warns about this case.
		self := policy.SelfExclusion{Exclude: !req.IncludeSelf}
		if strings.TrimSpace(req.SelfIP) != "" || strings.TrimSpace(req.SelfMAC) != "" {
			self.IP = strings.TrimSpace(req.SelfIP)
			self.MAC = strings.TrimSpace(req.SelfMAC)
			if self.IP != "" {
				if dev, ok := s.findDeviceByIP(self.IP); ok && self.MAC == "" {
					self.MAC = dev.PrimaryMAC
				}
			}
		} else if selfIP := clientIP(r); selfIP != "" {
			self.IP = selfIP
			if dev, ok := s.findDeviceByIP(selfIP); ok {
				self.MAC = dev.PrimaryMAC
			}
		}
		reason := strings.TrimSpace(req.Reason)
		if !req.DryRun && s.freeze.IsActive() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "already_frozen", "latch": true,
				"hint": "Freeze is already ON. Unblock first before starting a new run.",
			})
			return
		}
		if !req.DryRun && !s.tryAction() {
			http.Error(w, "a freeze/unfreeze operation is already running; wait and retry", http.StatusConflict)
			return
		}
		adapter, dryRun, includeSelf := req.Adapter, req.DryRun, req.IncludeSelf
		go func() {
			defer s.actionDone()
			applied, skipped, failed := s.freeze.Activate(adapter, ttl, reason, dryRun, self)
			s.policyEngine.Audit(actor, "freeze", "network", s.siteID, fmt.Sprintf("reason=%q applied=%d skipped=%d failed=%d latched=%v include_self=%v self_ip=%s", reason, applied, skipped, len(failed), s.freeze.IsActive(), includeSelf, self.IP), "success")
		}()
		selfWarning := ""
		if !req.IncludeSelf && (self.IP == "" || self.IP == "127.0.0.1" || self.IP == "::1" || self.IP == "::ffff:127.0.0.1") {
			selfWarning = "you may cut yourself too: pick your device or open the dashboard via your LAN IP"
		}
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "freezing", "latch": !req.DryRun,
			"self_ip": self.IP, "self_cut": req.IncludeSelf,
			"self_warning": selfWarning,
		})
		return
	}
	if r.Method == http.MethodDelete {
		if !s.freeze.IsActive() && len(s.policyEngine.ListEnforcements()) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "already_released"})
			return
		}
		if !s.tryAction() {
			http.Error(w, "a freeze/unfreeze operation is already running; wait and retry", http.StatusConflict)
			return
		}
		s.freeze.Unlatch()
		go func() {
			defer s.actionDone()
			lifted := s.freeze.Deactivate(actor)
			s.policyEngine.Audit(actor, "unfreeze", "network", s.siteID, fmt.Sprintf("lifted=%d", lifted), "success")
		}()
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "unfreezing"})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		al := s.policyEngine.GetAllowlist()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(al)
		return
	} else if r.Method == http.MethodPut {
		var al models.Allowlist
		if err := json.NewDecoder(r.Body).Decode(&al); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.policyEngine.UpdateAllowlist(al)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(al)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs := s.policyEngine.ListAuditLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	top := s.telemetryEngine.TopTalkers(20)
	if top == nil {
		top = []traffic.DeviceTrafficStats{}
	}
	// Include totals so dashboard can show total bandwidth (gap #5).
	var totalRx, totalTx uint64
	var totalRxRate, totalTxRate float64
	hasActivity := false
	for _, t := range top {
		totalRx += t.RxBytes
		totalTx += t.TxBytes
		totalRxRate += t.RxRateBps
		totalTxRate += t.TxRateBps
		if t.RxBytes+t.TxBytes > 0 {
			hasActivity = true
		}
	}
	iface := s.telemetryEngine.GetInterfaceTotals()
	src := s.telemetryEngine.GetTrafficSource()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"top_talkers":       top,
		"total_rx_bytes":    totalRx,
		"total_tx_bytes":    totalTx,
		"total_rx_rate_bps": totalRxRate,
		"total_tx_rate_bps": totalTxRate,
		"total_rate_bps":    totalRxRate + totalTxRate,
		"source":            src,
		"per_ip_available":  hasActivity && src != "unavailable",
		"gateway_totals":    iface,
	})
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Accept both raw Observation and lan-agent Event envelope
	// {"type":"device.seen","data":{device}} (fixes lan-agent schema mismatch).
	var raw json.RawMessage
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		http.Error(w, fmt.Sprintf("invalid observation json: %v", err), http.StatusBadRequest)
		return
	}
	observations := s.decodeObservations(raw)
	if len(observations) == 0 {
		http.Error(w, "no valid observation found in payload", http.StatusBadRequest)
		return
	}

	var lastDev *models.Device
	var lastAlert *models.Alert
	for _, obs := range observations {
		if obs.Timestamp.IsZero() {
			obs.Timestamp = time.Now().UTC()
		}
		dev := s.fusionEngine.IngestObservation(obs)
		if dev != nil {
			lastDev = dev
			s.telemetryEngine.RegisterDeviceBinding(dev.ID, dev.PrimaryIP, dev.PrimaryMAC)
		}
		if alert := s.detectionEngine.AnalyzeObservation(obs); alert != nil {
			lastAlert = alert
		}
		// Feed DHCP server observations into rogue-DHCP detection.
		if observations[0].Source == "dhcp" || obs.Source == "dhcp" {
			if srvIP, ok := obs.Attributes["dhcp_server_ip"].(string); ok && srvIP != "" {
				if alert := s.detectionEngine.InspectDHCPOffer(srvIP, obs.MAC); alert != nil {
					lastAlert = alert
				}
			}
		}
	}

	resp := map[string]interface{}{
		"status": "ingested",
		"count":  len(observations),
		"device": lastDev,
		"alert":  lastAlert,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// decodeObservations handles Observation, []Observation, and Event envelopes.
func (s *Server) decodeObservations(raw json.RawMessage) []models.Observation {
	// 1. Single observation
	var obs models.Observation
	if err := json.Unmarshal(raw, &obs); err == nil && (obs.MAC != "" || obs.IP != "") {
		return []models.Observation{obs}
	}
	// 2. Batch
	var batch []models.Observation
	if err := json.Unmarshal(raw, &batch); err == nil && len(batch) > 0 {
		return batch
	}
	// 3. Event envelope {type, data} from lan-agent
	var env struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data) > 0 {
		// data may be a Device
		var dev models.Device
		if err := json.Unmarshal(env.Data, &dev); err == nil && (dev.PrimaryMAC != "" || dev.PrimaryIP != "") {
			return []models.Observation{{
				Timestamp: dev.LastSeen,
				Source:    "lan_agent",
				MAC:       dev.PrimaryMAC,
				IP:        dev.PrimaryIP,
				Hostname:  dev.DisplayName,
				Vendor:    dev.Vendor,
				Interface: dev.Attachment.Interface,
				VLAN:      dev.Attachment.VLAN,
			}}
		}
		// data may itself be an observation
		var inner models.Observation
		if err := json.Unmarshal(env.Data, &inner); err == nil && (inner.MAC != "" || inner.IP != "") {
			return []models.Observation{inner}
		}
	}
	return nil
}

func (s *Server) handleRemediation(w http.ResponseWriter, r *http.Request) {
	if s.autoRem == nil {
		http.Error(w, "auto-remediation not configured", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auto_remediation_active": s.autoRem.IsEnabled(),
			"default_ttl_seconds":     600,
		})
		return
	} else if r.Method == http.MethodPost {
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Enabled != nil {
			s.autoRem.SetEnabled(*req.Enabled)
			s.policyEngine.Audit(actorFromRequest(r), "auto_remediation_toggle", "remediation", "auto", fmt.Sprintf("enabled=%v", *req.Enabled), "success")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auto_remediation_active": s.autoRem.IsEnabled(),
		})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pols := s.policyEngine.ListPolicies()
		if pols == nil {
			pols = []*models.Policy{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pols)
	case http.MethodPost:
		var p models.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.ID == "" {
			p.ID = uuid.New().String()
		}
		if p.Name == "" {
			p.Name = "policy-" + p.ID[:8]
		}
		s.policyEngine.SavePolicy(&p)
		_ = s.store.SavePolicy(r.Context(), &p)
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&p)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicyDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		http.Error(w, "Policy ID required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, ok := s.policyEngine.GetPolicy(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	case http.MethodPatch, http.MethodPut:
		p, ok := s.policyEngine.GetPolicy(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var patch models.Policy
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		patch.ID = id
		if patch.CreatedAt.IsZero() {
			patch.CreatedAt = p.CreatedAt
		}
		s.policyEngine.SavePolicy(&patch)
		_ = s.store.SavePolicy(r.Context(), &patch)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&patch)
	case http.MethodDelete:
		if !s.policyEngine.DeletePolicy(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.URL.Query().Get("action") // quarantine | rate_limit | shaping | ""
	if action == "shaping" {
		action = "rate_limit"
	}
	ranked := s.policyEngine.RankedAdapters(r.Context(), action)
	if ranked == nil {
		ranked = []adapters.RankedAdapter{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"action":   action,
		"adapters": ranked,
		"best":     bestName(ranked),
	})
}

func bestName(ranked []adapters.RankedAdapter) string {
	for _, x := range ranked {
		if x.Recommended && x.Available && x.SupportsAction {
			return x.Info.Name
		}
	}
	for _, x := range ranked {
		if x.Recommended {
			return x.Info.Name
		}
	}
	return ""
}

func (s *Server) handleIntegrationDetail(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/integrations/")
	parts := strings.Split(name, "/")
	name = parts[0]
	if name == "" {
		http.Error(w, "Integration name required", http.StatusBadRequest)
		return
	}
	a, err := s.policyEngine.GetAdapter(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// /integrations/{id}/capabilities — full guidance card.
	info := a.Describe()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"name":                info.Name,
		"label":               info.Label,
		"kind":                info.Kind,
		"effectiveness_1_5":   info.Effectiveness,
		"capabilities":        info.Capabilities,
		"available":           a.IsAvailable(r.Context()),
		"recommended_when":    info.RecommendedWhen,
		"requires":            info.Requires,
		"description":         info.Description,
		"warning":             info.Warning,
		"lab_only":            info.LabOnly,
		"test_only":           info.TestOnly,
		"supports_quarantine": info.SupportsQuarantine,
		"supports_shaping":    info.SupportsShaping,
	})
}

func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	if s.sched == nil {
		http.Error(w, "scheduler not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := s.sched.ListSchedules()
		if list == nil {
			list = []*policy.PolicySchedule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var sched policy.PolicySchedule
		if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if sched.ID == "" {
			sched.ID = uuid.New().String()
		}
		if sched.DeviceID == "" {
			http.Error(w, "device_id is required", http.StatusBadRequest)
			return
		}
		if sched.Action == "" {
			sched.Action = models.ActionQuarantine
		}
		if sched.StartHour < 0 || sched.StartHour > 23 || sched.EndHour < 0 || sched.EndHour > 23 ||
			sched.StartMin < 0 || sched.StartMin > 59 || sched.EndMin < 0 || sched.EndMin > 59 {
			http.Error(w, "hours must be 0-23 and minutes 0-59", http.StatusBadRequest)
			return
		}
		sched.Active = true
		s.sched.AddSchedule(&sched)
		s.policyEngine.Audit(actorFromRequest(r), "schedule_create", "schedule", sched.ID, fmt.Sprintf("device=%s action=%s %02d:%02d-%02d:%02d", sched.DeviceID, sched.Action, sched.StartHour, sched.StartMin, sched.EndHour, sched.EndMin), "success")
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&sched)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	if s.sched == nil {
		http.Error(w, "scheduler not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/schedules/"), "/")[0]
	if id == "" {
		http.Error(w, "Schedule ID required", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.sched.RemoveSchedule(id)
	s.policyEngine.Audit(actorFromRequest(r), "schedule_delete", "schedule", id, "removed", "success")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	if s.dispatcher == nil {
		http.Error(w, "webhook dispatcher not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := s.dispatcher.ListEndpoints()
		if list == nil {
			list = []*notify.WebhookEndpoint{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var ep notify.WebhookEndpoint
		if err := json.NewDecoder(r.Body).Decode(&ep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ep.ID == "" {
			ep.ID = uuid.New().String()
		}
		if ep.URL == "" || (!strings.HasPrefix(ep.URL, "http://") && !strings.HasPrefix(ep.URL, "https://")) {
			http.Error(w, "valid http(s) url is required", http.StatusBadRequest)
			return
		}
		ep.Enabled = true
		s.dispatcher.RegisterEndpoint(&ep)
		s.policyEngine.Audit(actorFromRequest(r), "webhook_create", "webhook", ep.ID, fmt.Sprintf("url=%s severity=%s", ep.URL, ep.MinSeverity), "success")
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&ep)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWebhookDetail(w http.ResponseWriter, r *http.Request) {
	if s.dispatcher == nil {
		http.Error(w, "webhook dispatcher not configured", http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if id == "" {
		http.Error(w, "Webhook ID required", http.StatusBadRequest)
		return
	}
	if len(parts) > 1 && parts[1] == "test" && r.Method == http.MethodPost {
		now := time.Now().UTC()
		s.dispatcher.DispatchAlert(r.Context(), &models.Alert{
			ID:                uuid.New().String(),
			Type:              models.AlertUnknownDevice,
			Severity:          models.SeverityInfo,
			Confidence:        1.0,
			FirstSeen:         now,
			LastSeen:          now,
			Evidence:          []models.AlertEvidence{{Timestamp: now, Description: "Manual test notification from Open-NetCut"}},
			RecommendedAction: "No action needed (test)",
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "test dispatched"})
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.dispatcher.RemoveEndpoint(id)
	s.policyEngine.Audit(actorFromRequest(r), "webhook_delete", "webhook", id, "removed", "success")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleExportDevicesCSV(w http.ResponseWriter, r *http.Request) {
	devices := s.fusionEngine.ListDevices()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=open-netcut-devices.csv")

	fmt.Fprintln(w, "ID,Name,PrimaryIP,PrimaryMAC,Vendor,TrustState,RiskScore,IsOnline,FirstSeen,LastSeen")
	for _, d := range devices {
		fmt.Fprintf(w, "%q,%q,%q,%q,%q,%q,%d,%t,%q,%q\n",
			d.ID, d.DisplayName, d.PrimaryIP, d.PrimaryMAC, d.Vendor, d.TrustState, d.RiskScore, d.IsOnline,
			d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339))
	}
}

func (s *Server) handleExportAuditCSV(w http.ResponseWriter, r *http.Request) {
	logs := s.policyEngine.ListAuditLogs()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=open-netcut-audit.csv")

	fmt.Fprintln(w, "ID,Timestamp,Actor,Action,TargetType,TargetID,Status,Details")
	for _, l := range logs {
		fmt.Fprintf(w, "%q,%q,%q,%q,%q,%q,%q,%q\n",
			l.ID, l.Timestamp.Format(time.RFC3339), l.Actor, l.Action, l.TargetType, l.TargetID, l.Status, l.Details)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Require same-origin or configured origin; coder/websocket validates Origin
	// when OriginPatterns is set. Allow localhost dev + ALLOWED_ORIGIN.
	patterns := []string{"localhost:*", "127.0.0.1:*"}
	if ao := os.Getenv("ALLOWED_ORIGIN"); ao != "" {
		// ALLOWED_ORIGIN is a full URL like https://netcut.example.com
		h := strings.TrimPrefix(strings.TrimPrefix(ao, "https://"), "http://")
		h = strings.Split(h, "/")[0]
		if h != "" {
			patterns = append(patterns, h)
		}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: patterns,
	})
	if err != nil {
		log.Printf("WebSocket accept error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "closing connection")

	sub := s.eventBus.Subscribe(50)
	defer s.eventBus.Unsubscribe(sub)

	ctx := conn.CloseRead(r.Context())

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-sub:
			if !ok {
				return
			}
			msg, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err = conn.Write(writeCtx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Reflect validated origin instead of "*".
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else {
		w.Header().Set("Access-Control-Allow-Origin", s.allowedOrigin())
	}

	sub := s.eventBus.Subscribe(50)
	defer s.eventBus.Unsubscribe(sub)

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case evt, ok := <-sub:
			if !ok {
				return
			}
			msg, _ := json.Marshal(evt)
			fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", strconv.FormatUint(evt.Sequence, 10), evt.Type, msg)
			flusher.Flush()
		}
	}
}
