package discovery

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// IdentityFusionEngine correlates multi-protocol observations into unified Device profiles.
type IdentityFusionEngine struct {
	mu           sync.RWMutex
	devicesByID  map[string]*models.Device
	devicesByMAC map[string]*models.Device
	devicesByIP  map[string]*models.Device
	obsHistory   map[string][]models.Observation // deviceID -> recent observations (cap 100)
	lastPublish  map[string]time.Time // deviceID -> last device.updated broadcast (WS storm guard)
	eventBus     *events.EventBus
	siteID       string
	stopCh       chan struct{}
}

// NewIdentityFusionEngine creates and initializes the engine.
func NewIdentityFusionEngine(siteID string, eventBus *events.EventBus) *IdentityFusionEngine {
	if siteID == "" {
		siteID = "default"
	}
	fe := &IdentityFusionEngine{
		devicesByID:  make(map[string]*models.Device),
		devicesByMAC: make(map[string]*models.Device),
		devicesByIP:  make(map[string]*models.Device),
		obsHistory:   make(map[string][]models.Observation),
		lastPublish:  make(map[string]time.Time),
		eventBus:     eventBus,
		siteID:       siteID,
		stopCh:       make(chan struct{}),
	}

	go fe.idlePruner()
	return fe
}

// IngestObservation processes a new sensor signal and updates or registers the device.
func (fe *IdentityFusionEngine) IngestObservation(obs models.Observation) *models.Device {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	cleanMAC := strings.ToLower(strings.TrimSpace(obs.MAC))
	cleanIP := strings.TrimSpace(obs.IP)

	if cleanMAC == "" && cleanIP == "" {
		return nil
	}

	now := time.Now().UTC()
	if obs.Timestamp.IsZero() {
		obs.Timestamp = now
	}

	// Weak signals (e.g. DHCP leases) describe bindings that may be hours
	// stale: a lease file remembers departed devices long after they leave.
	// They must never create devices, trigger merges, move IP bindings, or
	// refresh liveness — they only enrich an already-known (by MAC) device.
	// Live presence comes from ARP/neighbor sightings; without this, stale
	// leases resurrect phantom devices and rename whoever holds the IP now.
	if isWeakSource(obs.Source) {
		return fe.ingestWeakObservation(obs, cleanMAC, cleanIP, now)
	}

	var device *models.Device
	isNew := false

	// Attempt resolution with automatic record merging to prevent duplicates
	if cleanMAC != "" && cleanIP != "" {
		devByMAC := fe.devicesByMAC[cleanMAC]
		devByIP := fe.devicesByIP[cleanIP]
		if devByMAC != nil && devByIP != nil && devByMAC.ID != devByIP.ID {
			// Merge devByIP into devByMAC to eliminate duplicate
			delete(fe.devicesByID, devByIP.ID)
			delete(fe.devicesByIP, devByIP.PrimaryIP)
			for k, v := range devByIP.Metadata {
				if _, exists := devByMAC.Metadata[k]; !exists {
					devByMAC.Metadata[k] = v
				}
			}
			for _, svc := range devByIP.Services {
				devByMAC.Services = append(devByMAC.Services, svc)
			}
			device = devByMAC
			device.PrimaryIP = cleanIP
			fe.devicesByIP[cleanIP] = device
		} else if devByMAC != nil {
			device = devByMAC
		} else if devByIP != nil {
			device = devByIP
		}
	} else if cleanMAC != "" {
		device = fe.devicesByMAC[cleanMAC]
	} else if cleanIP != "" {
		device = fe.devicesByIP[cleanIP]
	}

	// Reject creation of new devices without a MAC address to prevent ghost duplicates
	if device == nil && cleanMAC == "" {
		return nil
	}

	if obs.Timestamp.IsZero() {
		obs.Timestamp = now
	}

	// Online-state hysteresis (anti-flap):
	// A single STALE/negative observation must NEVER flip a device offline.
	// Positive sightings set online immediately; offline happens ONLY via
	// idlePruner after grace period with no sightings. Negative signals
	// (is_online=false, FAILED/INCOMPLETE neigh states) are recorded in
	// history but do not move LastSeen backwards or clear IsOnline.
	negativeSignal := false
	if val, ok := obs.Attributes["is_online"].(bool); ok && !val {
		negativeSignal = true
	}
	if st, ok := obs.Attributes["neigh_state"].(string); ok {
		switch st {
		case "FAILED", "INCOMPLETE":
			negativeSignal = true
		}
	}
	if obs.Source == "ip_neigh" && negativeSignal {
		// Record history for forensics but don't touch live state.
		// (Prevents UP->DOWN flap every scan when kernel reports STALE.)
		if device != nil {
			fe.obsHistory[device.ID] = append(fe.obsHistory[device.ID], obs)
			if len(fe.obsHistory[device.ID]) > 100 {
				fe.obsHistory[device.ID] = fe.obsHistory[device.ID][len(fe.obsHistory[device.ID])-100:]
			}
		}
		return device
	}

	var wasOffline bool
	if device == nil {
		isNew = true
		deviceID := uuid.New().String()
		device = &models.Device{
			ID:          deviceID,
			SiteID:      fe.siteID,
			PrimaryMAC:  cleanMAC,
			PrimaryIP:   cleanIP,
			TrustState:  models.TrustStateUnknown,
			RiskScore:   10, // baseline for unknown device
			IsOnline:    true, // new sighting = online
			FirstSeen:   obs.Timestamp,
			LastSeen:    obs.Timestamp,
			Metadata:    make(map[string]interface{}),
			Labels:      make(map[string]string),
			Addresses:   make([]models.DeviceAddress, 0),
			Services:    make([]models.DeviceService, 0),
			Attachment: models.DeviceAttachment{
				Interface: obs.Interface,
				VLAN:      obs.VLAN,
			},
		}

		if cleanMAC != "" {
			device.Vendor = LookupVendor(cleanMAC)
			if device.Vendor != "" && device.Vendor != "Unknown Vendor" {
				device.Metadata["vendor_source"] = "oui"
			}
		}

		fe.devicesByID[deviceID] = device
		if cleanMAC != "" {
			fe.devicesByMAC[cleanMAC] = device
		}
		if cleanIP != "" {
			fe.devicesByIP[cleanIP] = device
		}
	} else {
		// Positive sighting: refresh LastSeen (never backwards) and
		// flap UP immediately — even if pruner marked it offline.
		if obs.Timestamp.After(device.LastSeen) {
			device.LastSeen = obs.Timestamp
		}
		wasOffline = !device.IsOnline
		device.IsOnline = true

		if cleanMAC != "" && device.PrimaryMAC == "" {
			device.PrimaryMAC = cleanMAC
			fe.devicesByMAC[cleanMAC] = device
		}
		if cleanIP != "" && device.PrimaryIP != cleanIP {
			if device.PrimaryIP != "" {
				delete(fe.devicesByIP, device.PrimaryIP)
			}
			device.PrimaryIP = cleanIP
			fe.devicesByIP[cleanIP] = device
		}
		// Refresh the OUI vendor on every sighting (unless a fingerprint
		// override is in force) so corrected database entries propagate to
		// existing records instead of sticking forever.
		if cleanMAC != "" {
			fe.refreshVendor(device, cleanMAC)
		}
	}

	// Update address history
	if cleanIP != "" || cleanMAC != "" {
		fe.updateAddress(device, cleanIP, cleanMAC, obs.Source, obs.Timestamp)
	}

	// Enrich Services if present in observation attributes
	if srvName, ok := obs.Attributes["service_name"].(string); ok && srvName != "" {
		port, _ := obs.Attributes["service_port"].(int)
		proto, _ := obs.Attributes["service_proto"].(string)
		if proto == "" {
			proto = "tcp"
		}
		fe.addOrUpdateService(device, srvName, proto, port, obs.Source, obs.Timestamp)
	}

	// Copy custom attributes (never let a signal clear liveness state)
	for k, v := range obs.Attributes {
		if k == "is_online" {
			continue
		}
		device.Metadata[k] = v
	}
	if fpVendor, ok := obs.Attributes["fingerprint_vendor"].(string); ok && fpVendor != "" {
		device.Vendor = fpVendor
		device.Metadata["vendor_source"] = "fingerprint"
	}

	// Curated hostname: stronger sources win, ties keep the incumbent so a
	// single stray packet (mDNS query, stale PTR) can't rename a device.
	fe.adoptHostname(device, obs.Source, obs.Hostname)
	if ptr, ok := obs.Attributes["ptr_hostname"].(string); ok && ptr != "" {
		fe.adoptHostname(device, "ptr", ptr)
	}
	fe.refineDisplayName(device)

	// Re-evaluate risk score
	fe.computeRiskScore(device)

	// Record observation history (cap 100 per device)
	fe.obsHistory[device.ID] = append(fe.obsHistory[device.ID], obs)
	if len(fe.obsHistory[device.ID]) > 100 {
		fe.obsHistory[device.ID] = fe.obsHistory[device.ID][len(fe.obsHistory[device.ID])-100:]
	}

	// Broadcast event — throttled to stop WS storms.
	// device.seen always fires; device.updated at most once per 5s per device
	// unless the device just flapped back online (immediate, for stable UI).
	if isNew {
		if fe.eventBus != nil {
			fe.eventBus.Publish(events.EventDeviceSeen, fe.siteID, device)
			fe.lastPublish[device.ID] = now
		}
	} else {
		if fe.eventBus != nil {
			last, ok := fe.lastPublish[device.ID]
			flappedUp := wasOffline // offline->online transition: notify now
			if flappedUp || !ok || now.Sub(last) >= 5*time.Second {
				fe.eventBus.Publish(events.EventDeviceUpdated, fe.siteID, device)
				fe.lastPublish[device.ID] = now
			}
		}
	}

	return device
}

// refreshVendor recomputes the OUI vendor for a sighted MAC. A fingerprint
// override (active interrogation) always wins and is never downgraded.
func (fe *IdentityFusionEngine) refreshVendor(d *models.Device, cleanMAC string) {
	if d.Metadata == nil {
		d.Metadata = make(map[string]interface{})
	}
	if src, _ := d.Metadata["vendor_source"].(string); src == "fingerprint" {
		return
	}
	if oui := LookupVendor(cleanMAC); oui != "" && oui != "Unknown Vendor" {
		d.Vendor = oui
		d.Metadata["vendor_source"] = "oui"
	} else if d.Vendor == "" {
		d.Vendor = "Unknown Vendor"
	}
}

func (fe *IdentityFusionEngine) updateAddress(d *models.Device, ip, mac, source string, ts time.Time) {	for i := range d.Addresses {
		if d.Addresses[i].IP == ip && d.Addresses[i].MAC == mac {
			d.Addresses[i].LastSeen = ts
			d.Addresses[i].Source = source
			return
		}
	}
	d.Addresses = append(d.Addresses, models.DeviceAddress{
		DeviceID:   d.ID,
		IP:         ip,
		MAC:        mac,
		Source:     source,
		Confidence: 0.9,
		FirstSeen:  ts,
		LastSeen:   ts,
	})
}

func (fe *IdentityFusionEngine) addOrUpdateService(d *models.Device, name, proto string, port int, source string, ts time.Time) {
	for i := range d.Services {
		if d.Services[i].Name == name && d.Services[i].Port == port {
			d.Services[i].LastSeen = ts
			return
		}
	}
	d.Services = append(d.Services, models.DeviceService{
		DeviceID: d.ID,
		Name:     name,
		Protocol: proto,
		Port:     port,
		Source:   source,
		LastSeen: ts,
	})
}

// weakSources are signals that describe bindings which may be long stale
// (DHCP leases outlive presence by hours). They enrich but never create.
var weakSources = map[string]bool{"dhcp": true}

func isWeakSource(source string) bool {
	return weakSources[strings.ToLower(strings.TrimSpace(source))]
}

// hostnameRank orders name sources by trust. Active interrogations
// (NetBIOS/fingerprint, local agent) beat self-announcements (mDNS answers,
// fresh DHCP hostnames), which beat reverse-DNS guesses. A wrong name from a
// weak source must never overwrite a name from a stronger one.
func hostnameRank(source string) int {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "fingerprint", "netbios", "local_interface", "lan_agent":
		return 3
	case "mdns", "dhcp", "upnp":
		return 2
	default:
		return 1 // ptr, arp_proc, ip_neigh, ssdp, router, discovery_fusion
	}
}

// metaRank reads the curated hostname rank, tolerating JSON round-trips
// (numbers decode as float64 after a snapshot reload).
func metaRank(m map[string]interface{}) int {
	switch r := m["hostname_rank"].(type) {
	case int:
		return r
	case float64:
		return int(r)
	case int64:
		return int(r)
	}
	return 0
}

// adoptHostname curates Metadata["hostname"]: stronger ranks overwrite weaker
// ones; ties keep the incumbent so names never flap between equal sources.
// Rank 5 is reserved for manual operator renames and beats everything.
// Returns true when the curated name changed.
func (fe *IdentityFusionEngine) adoptHostname(d *models.Device, source, name string) bool {
	name = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	// Service-discovery artifacts are never hostnames: mDNS service types
	// ("_googlecast._tcp.local") and service instances ("TV._http._tcp.local")
	// always carry _tcp/_udp markers or a leading underscore. (Note: real
	// Windows computer names may contain spaces, e.g. "KJ SST", so spaces
	// must NOT be rejected.) Without this, one enumeration packet renames a
	// real device to "_googlecast._tcp.local".
	if strings.HasPrefix(name, "_") ||
		strings.Contains(name, "._tcp") ||
		strings.Contains(name, "._udp") {
		return false
	}
	if d.Metadata == nil {
		d.Metadata = make(map[string]interface{})
	}
	rank := hostnameRank(source)
	if source == "_gateway" || name == "_gateway" {
		rank = 4 // explicit infrastructure marker outranks everything
		name = "_gateway"
	}
	curRank := metaRank(d.Metadata)
	if cur, ok := d.Metadata["hostname"].(string); ok && cur != "" && rank <= curRank {
		return false
	}
	d.Metadata["hostname"] = name
	d.Metadata["hostname_rank"] = rank
	d.Metadata["hostname_source"] = source
	return true
}

// ingestWeakObservation enriches an already-known device (resolved strictly by
// MAC) without creating records, merging identities, moving IP bindings, or
// touching liveness. Unknown MACs are ignored — ARP will create the device
// within seconds if it is really on the LAN.
func (fe *IdentityFusionEngine) ingestWeakObservation(obs models.Observation, cleanMAC, cleanIP string, now time.Time) *models.Device {
	if cleanMAC == "" {
		return nil
	}
	device := fe.devicesByMAC[cleanMAC]
	if device == nil {
		return nil
	}
	changed := fe.adoptHostname(device, obs.Source, obs.Hostname)
	if ptr, ok := obs.Attributes["ptr_hostname"].(string); ok && ptr != "" {
		if fe.adoptHostname(device, "ptr", ptr) {
			changed = true
		}
	}
	if cleanIP != "" || cleanMAC != "" {
		fe.updateAddress(device, cleanIP, cleanMAC, obs.Source, obs.Timestamp)
	}
	for k, v := range obs.Attributes {
		if k == "is_online" {
			continue
		}
		device.Metadata[k] = v
	}
	if changed {
		fe.refineDisplayName(device)
		fe.computeRiskScore(device)
	}
	fe.obsHistory[device.ID] = append(fe.obsHistory[device.ID], obs)
	if len(fe.obsHistory[device.ID]) > 100 {
		fe.obsHistory[device.ID] = fe.obsHistory[device.ID][len(fe.obsHistory[device.ID])-100:]
	}
	if changed && fe.eventBus != nil {
		last, ok := fe.lastPublish[device.ID]
		if !ok || now.Sub(last) >= 5*time.Second {
			fe.eventBus.Publish(events.EventDeviceUpdated, fe.siteID, device)
			fe.lastPublish[device.ID] = now
		}
	}
	return device
}

func (fe *IdentityFusionEngine) refineDisplayName(d *models.Device) {
	if d.Metadata != nil {
		if isLocal, ok := d.Metadata["is_local_host"].(bool); ok && isLocal {
			d.DisplayName = fmt.Sprintf("This Machine (%s)", d.PrimaryIP)
			return
		}
	}
	host, _ := d.Metadata["hostname"].(string)
	if host == "_gateway" {
		d.DisplayName = fmt.Sprintf("Gateway Router (%s)", d.PrimaryIP)
		return
	}
	if devType, ok := d.Metadata["device_type"].(string); ok && devType != "" {
		if host != "" && host != d.PrimaryIP {
			d.DisplayName = fmt.Sprintf("%s (%s)", devType, host)
			return
		}
		d.DisplayName = fmt.Sprintf("%s (%s)", devType, d.PrimaryIP)
		return
	}
	if host != "" {
		d.DisplayName = host
		return
	}

	// Refine based on Vendor, Mobile, or Host
	if d.Vendor == "Private / Randomized MAC (Mobile)" {
		d.DisplayName = fmt.Sprintf("Mobile Device (%s)", d.PrimaryIP)
	} else if d.Vendor != "" && d.Vendor != "Unknown Vendor" {
		d.DisplayName = fmt.Sprintf("%s (%s)", d.Vendor, d.PrimaryIP)
	} else if d.PrimaryIP != "" {
		d.DisplayName = fmt.Sprintf("Device-%s", d.PrimaryIP)
	} else if d.PrimaryMAC != "" {
		d.DisplayName = fmt.Sprintf("Device-%s", d.PrimaryMAC)
	} else {
		d.DisplayName = fmt.Sprintf("Device-%s", d.ID[:8])
	}
}

func (fe *IdentityFusionEngine) computeRiskScore(d *models.Device) {
	score := 0
	if d.TrustState == models.TrustStateQuarantined {
		score += 50
	}
	if strings.Contains(d.Vendor, "Randomized") {
		score += 15
	}
	if d.Vendor == "Unknown Vendor" {
		score += 20
	}
	if len(d.Addresses) > 3 {
		score += 25 // Multiple IP addresses / address churn
	}
	if score > 100 {
		score = 100
	}
	d.RiskScore = score
}

// GetDevice returns a device by its ID.
func (fe *IdentityFusionEngine) GetDevice(id string) (*models.Device, bool) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	d, ok := fe.devicesByID[id]
	return d, ok
}

// GetDeviceByMAC returns a device by MAC address (any separator case).
// Lets operators act on "the device with this MAC" without hunting IDs.
func (fe *IdentityFusionEngine) GetDeviceByMAC(mac string) (*models.Device, bool) {
	clean := strings.ToLower(strings.TrimSpace(mac))
	clean = strings.ReplaceAll(clean, "-", ":")
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	d, ok := fe.devicesByMAC[clean]
	return d, ok
}

// ListDevices returns a copy of all tracked devices, strictly deduplicated by MAC and IP.
// Sorted by IP for a stable UI order (no reshuffle every refresh).
func (fe *IdentityFusionEngine) ListDevices() []*models.Device {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	seenMAC := make(map[string]bool)
	seenIP := make(map[string]bool)
	list := make([]*models.Device, 0, len(fe.devicesByID))

	for _, d := range fe.devicesByID {
		if d.PrimaryMAC == "" && d.PrimaryIP == "" {
			continue
		}
		if d.PrimaryMAC != "" {
			if seenMAC[d.PrimaryMAC] {
				continue
			}
			seenMAC[d.PrimaryMAC] = true
		}
		if d.PrimaryIP != "" {
			if seenIP[d.PrimaryIP] {
				continue
			}
			seenIP[d.PrimaryIP] = true
		}
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].PrimaryIP != list[j].PrimaryIP {
			return list[i].PrimaryIP < list[j].PrimaryIP
		}
		return list[i].PrimaryMAC < list[j].PrimaryMAC
	})
	return list
}

// GetObservationHistory returns recent raw observations for a device (newest last).
func (fe *IdentityFusionEngine) GetObservationHistory(deviceID string, limit int) []models.Observation {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	hist := fe.obsHistory[deviceID]
	if len(hist) == 0 {
		return []models.Observation{}
	}
	if limit > 0 && len(hist) > limit {
		hist = hist[len(hist)-limit:]
	}
	out := make([]models.Observation, len(hist))
	copy(out, hist)
	return out
}

// SnapshotDevices returns operator-meaningful device state for persistence:
// devices with a manual name (rank 5) or a non-default trust decision.
// Everything else re-learns within seconds of a scan, so persisting it all
// would only resurrect stale phantoms.
func (fe *IdentityFusionEngine) SnapshotDevices() []*models.Device {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	var out []*models.Device
	for _, d := range fe.devicesByID {
		if metaRank(d.Metadata) != 5 && d.TrustState == models.TrustStateUnknown {
			continue
		}
		cp := *d
		// "quarantined" is enforcement-derived and enforcements are never
		// persisted — saving it would resurrect the label on every restart
		// with zero live cuts ("Unblock All but panel still shows
		// quarantined"). Manual trusted/restricted decisions persist.
		if cp.TrustState == models.TrustStateQuarantined {
			cp.TrustState = models.TrustStateUnknown
		}
		cp.Metadata = make(map[string]interface{}, len(d.Metadata))
		for k, v := range d.Metadata {
			cp.Metadata[k] = v
		}
		cp.Labels = make(map[string]string, len(d.Labels))
		for k, v := range d.Labels {
			cp.Labels[k] = v
		}
		cp.Addresses = nil
		cp.Services = nil
		out = append(out, &cp)
	}
	return out
}

// RestoreDevices reinstates persisted operator state after a restart.
// Unknown devices come back offline (live scans flip them online and refresh
// everything else); manual names and trust decisions apply immediately.
func (fe *IdentityFusionEngine) RestoreDevices(devs []*models.Device) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	for _, sd := range devs {
		if sd == nil || sd.ID == "" {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(sd.PrimaryMAC))
		if live, ok := fe.devicesByMAC[mac]; ok && mac != "" {
			// Device already discovered live: merge operator state only.
			if metaRank(sd.Metadata) == 5 {
				if live.Metadata == nil {
					live.Metadata = make(map[string]interface{})
				}
				if name, _ := sd.Metadata["hostname"].(string); name != "" {
					live.Metadata["hostname"] = name
					live.Metadata["hostname_rank"] = 5
					live.Metadata["hostname_source"] = "manual"
				}
			}
			// Never resurrect "quarantined": enforcements die with the
			// process, so a restored quarantine label can never match a
			// live cut (downgrade to unknown; old snapshots may contain it).
			if sd.TrustState != models.TrustStateUnknown && sd.TrustState != models.TrustStateQuarantined {
				live.TrustState = sd.TrustState
			}
			fe.refineDisplayName(live)
			fe.computeRiskScore(live)
			continue
		}
		if mac == "" {
			continue
		}
		cp := *sd
		if cp.TrustState == models.TrustStateQuarantined {
			cp.TrustState = models.TrustStateUnknown
		}
		cp.Metadata = make(map[string]interface{}, len(sd.Metadata))
		for k, v := range sd.Metadata {
			cp.Metadata[k] = v
		}
		cp.Labels = make(map[string]string, len(sd.Labels))
		for k, v := range sd.Labels {
			cp.Labels[k] = v
		}
		cp.Addresses = nil
		cp.Services = nil
		cp.IsOnline = false
		fe.devicesByID[cp.ID] = &cp
		fe.devicesByMAC[mac] = &cp
		if cp.PrimaryIP != "" {
			fe.devicesByIP[cp.PrimaryIP] = &cp
		}
		fe.refineDisplayName(&cp)
		fe.computeRiskScore(&cp)
	}
}

// SetTrustState updates the administrative trust state of a device.
func (fe *IdentityFusionEngine) SetTrustState(id string, state models.TrustState) error {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	device, ok := fe.devicesByID[id]
	if !ok {
		return fmt.Errorf("device %q not found", id)
	}
	device.TrustState = state
	fe.computeRiskScore(device)
	if fe.eventBus != nil {
		fe.eventBus.Publish(events.EventDeviceUpdated, fe.siteID, device)
	}
	return nil
}

// SetCustomName pins an operator-chosen display name at rank 5, outranking
// every automatic source (including future ones). Survives restarts via the
// JSON snapshot. Use ClearCustomName to return to automatic naming.
func (fe *IdentityFusionEngine) SetCustomName(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	fe.mu.Lock()
	defer fe.mu.Unlock()
	device, ok := fe.devicesByID[id]
	if !ok {
		return fmt.Errorf("device %q not found", id)
	}
	if device.Metadata == nil {
		device.Metadata = make(map[string]interface{})
	}
	device.Metadata["hostname"] = name
	device.Metadata["hostname_rank"] = 5
	device.Metadata["hostname_source"] = "manual"
	fe.refineDisplayName(device)
	if fe.eventBus != nil {
		fe.eventBus.Publish(events.EventDeviceUpdated, fe.siteID, device)
	}
	return nil
}

// ClearCustomName drops the manual override and re-derives the name from the
// best automatic source seen so far (replays stored observation history).
func (fe *IdentityFusionEngine) ClearCustomName(id string) error {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	device, ok := fe.devicesByID[id]
	if !ok {
		return fmt.Errorf("device %q not found", id)
	}
	delete(device.Metadata, "hostname")
	delete(device.Metadata, "hostname_rank")
	delete(device.Metadata, "hostname_source")
	for _, obs := range fe.obsHistory[id] {
		fe.adoptHostname(device, obs.Source, obs.Hostname)
		if ptr, ok := obs.Attributes["ptr_hostname"].(string); ok {
			fe.adoptHostname(device, "ptr", ptr)
		}
	}
	fe.refineDisplayName(device)
	if fe.eventBus != nil {
		fe.eventBus.Publish(events.EventDeviceUpdated, fe.siteID, device)
	}
	return nil
}

// idlePruner marks devices offline if not observed within 3 minutes.
func (fe *IdentityFusionEngine) idlePruner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fe.stopCh:
			return
		case <-ticker.C:
			fe.mu.Lock()
			now := time.Now().UTC()
			for _, d := range fe.devicesByID {
				if d.IsOnline && now.Sub(d.LastSeen) > 3*time.Minute {
					d.IsOnline = false
					if fe.eventBus != nil {
						fe.eventBus.Publish(events.EventDeviceOffline, fe.siteID, d)
					}
				}
			}
			fe.mu.Unlock()
		}
	}
}

// Stop halts background pruning.
func (fe *IdentityFusionEngine) Stop() {
	close(fe.stopCh)
}
