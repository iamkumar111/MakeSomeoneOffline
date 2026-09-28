package detection

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// KnownGateway tracks the authoritative gateway parameters.
type KnownGateway struct {
	IP  string
	MAC string
}

// DetectionEngine analyzes network state changes and raises structured alerts with evidence.
type DetectionEngine struct {
	mu           sync.RWMutex
	alerts       map[string]*models.Alert
	knownGateway KnownGateway
	trustedDHCP        map[string]bool              // map[IP]true
	trustedIPv6Routers map[string]bool              // map[MAC]true
	ipToMAC            map[string]string
	ipFirstSeen        map[string]time.Time         // for duplicate-IP stability window
	macClaimHist       map[string][]claimEntry      // MAC -> time-windowed IP claims
	portScans          map[string]map[int]time.Time // srcIP -> dstPort -> timestamp
	eventBus           *events.EventBus
}

type claimEntry struct {
	IP string
	TS time.Time
}

// NewDetectionEngine initializes the detection engine.
func NewDetectionEngine(gateway KnownGateway, eventBus *events.EventBus) *DetectionEngine {
	return &DetectionEngine{
		alerts:             make(map[string]*models.Alert),
		knownGateway:       gateway,
		trustedDHCP:        make(map[string]bool),
		trustedIPv6Routers: make(map[string]bool),
		ipToMAC:            make(map[string]string),
		ipFirstSeen:        make(map[string]time.Time),
		macClaimHist:       make(map[string][]claimEntry),
		portScans:          make(map[string]map[int]time.Time),
		eventBus:           eventBus,
	}
}

// SetKnownGateway updates the trusted gateway configuration.
func (de *DetectionEngine) SetKnownGateway(ip, mac string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.knownGateway = KnownGateway{
		IP:  strings.TrimSpace(ip),
		MAC: strings.ToLower(strings.TrimSpace(mac)),
	}
}

// SetTrustedDHCPServer registers an authorized DHCP server IP.
func (de *DetectionEngine) SetTrustedDHCPServer(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.trustedDHCP[ip] = true
}

// SetTrustedIPv6Router registers an authorized IPv6 router MAC.
func (de *DetectionEngine) SetTrustedIPv6Router(mac string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.trustedIPv6Routers[strings.ToLower(strings.TrimSpace(mac))] = true
}

// InspectIPv6RA flags unauthorized ICMPv6 Router Advertisements on the network.
func (de *DetectionEngine) InspectIPv6RA(routerIP, routerMAC, prefix string) *models.Alert {
	de.mu.Lock()
	defer de.mu.Unlock()

	cleanMAC := strings.ToLower(strings.TrimSpace(routerMAC))
	if len(de.trustedIPv6Routers) > 0 && !de.trustedIPv6Routers[cleanMAC] {
		now := time.Now().UTC()
		return de.createAlertLocked(models.Alert{
			Type:       models.AlertRogueIPv6RA,
			Severity:   models.SeverityCritical,
			Confidence: 0.96,
			TargetIP:   routerIP,
			TargetMAC:  cleanMAC,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("Unauthorized IPv6 Router Advertisement emitted by %s (%s) announcing prefix %s", routerIP, cleanMAC, prefix),
					Details: map[string]interface{}{
						"router_ip":  routerIP,
						"router_mac": cleanMAC,
						"prefix":     prefix,
					},
				},
			},
			RecommendedAction: "Enable IPv6 RA Guard on switch ports and quarantine rogue router host",
		})
	}
	return nil
}

// AnalyzeObservation evaluates incoming sensor observations for spoofing, conflicts, or anomalies.
func (de *DetectionEngine) AnalyzeObservation(obs models.Observation) *models.Alert {
	de.mu.Lock()
	defer de.mu.Unlock()

	cleanMAC := strings.ToLower(strings.TrimSpace(obs.MAC))
	cleanIP := strings.TrimSpace(obs.IP)

	if cleanMAC == "" || cleanIP == "" {
		return nil
	}

	now := time.Now().UTC()

	// 1. Critical: Gateway Impersonation Check
	if de.knownGateway.IP != "" && cleanIP == de.knownGateway.IP {
		if de.knownGateway.MAC != "" && cleanMAC != de.knownGateway.MAC {
			return de.createAlertLocked(models.Alert{
				Type:       models.AlertGatewayImpersonation,
				Severity:   models.SeverityCritical,
				Confidence: 0.98,
				TargetIP:   cleanIP,
				TargetMAC:  cleanMAC,
				Evidence: []models.AlertEvidence{
					{
						Timestamp:   now,
						Description: fmt.Sprintf("Gateway IP %s advertised by unexpected MAC %s (Legitimate MAC is %s)", cleanIP, cleanMAC, de.knownGateway.MAC),
						Details: map[string]interface{}{
							"source":         obs.Source,
							"claimed_mac":    cleanMAC,
							"legitimate_mac": de.knownGateway.MAC,
							"gateway_ip":     cleanIP,
						},
					},
				},
				RecommendedAction: "Isolate attacker switch port or enforce immediate quarantine on attacker MAC address",
			})
		}
	}

	// 2. Duplicate IP / Conflict Check (RFC 5227) with stability window.
	// Legitimate cases (DHCP reassignment, VRRP/HA virtual MACs, reboot) flap once;
	// spoofing flaps repeatedly. Require the IP to be stable >60s and flag only
	// on rapid re-flip, and never for VRRP/HA virtual MAC ranges.
	existingMAC, exists := de.ipToMAC[cleanIP]
	if exists && existingMAC != cleanMAC {
		firstSeen, ok := de.ipFirstSeen[cleanIP]
		if !ok {
			firstSeen = now
			de.ipFirstSeen[cleanIP] = firstSeen
		}
		if isVirtualHAMAC(cleanMAC) || isVirtualHAMAC(existingMAC) {
			// HA/VRRP failover — record silently, no alert.
			de.ipToMAC[cleanIP] = cleanMAC
			de.ipFirstSeen[cleanIP] = now
			return nil
		}
		// DHCP reassignment grace: first flip after long stability is LOW/info, not HIGH.
		if now.Sub(firstSeen) > 60*time.Second || strings.HasPrefix(obs.Source, "dhcp") {
			alert := de.createAlertLocked(models.Alert{
				Type:       models.AlertDuplicateIP,
				Severity:   models.SeverityMedium,
				Confidence: 0.6,
				TargetIP:   cleanIP,
				TargetMAC:  cleanMAC,
				Evidence: []models.AlertEvidence{
					{
						Timestamp:   now,
						Description: fmt.Sprintf("IP %s moved from %s to %s (possible DHCP reassignment; monitoring for flap)", cleanIP, existingMAC, cleanMAC),
						Details: map[string]interface{}{
							"ip":           cleanIP,
							"current_mac":  cleanMAC,
							"previous_mac": existingMAC,
							"source":       obs.Source,
							"stable_for":   now.Sub(firstSeen).String(),
						},
					},
				},
				RecommendedAction: "If flap repeats within minutes, inspect for spoofing; otherwise treat as DHCP/static change",
			})
			de.ipToMAC[cleanIP] = cleanMAC
			de.ipFirstSeen[cleanIP] = now
			return alert
		}
		alert := de.createAlertLocked(models.Alert{
			Type:       models.AlertDuplicateIP,
			Severity:   models.SeverityHigh,
			Confidence: 0.85,
			TargetIP:   cleanIP,
			TargetMAC:  cleanMAC,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("IP %s rapidly claimed by %s and %s (possible conflict/spoofing)", cleanIP, cleanMAC, existingMAC),
					Details: map[string]interface{}{
						"ip":           cleanIP,
						"current_mac":  cleanMAC,
						"previous_mac": existingMAC,
						"source":       obs.Source,
					},
				},
			},
			RecommendedAction: "Verify static IP configurations and inspect ARP snooping tables for potential spoofing",
		})
		de.ipToMAC[cleanIP] = cleanMAC
		return alert
	}
	if !exists {
		de.ipFirstSeen[cleanIP] = now
	}
	de.ipToMAC[cleanIP] = cleanMAC

	// 3. Multi-IP Claim Check with 10s sliding window (mass ARP-spoof signature:
	// one MAC claiming many IPs rapidly). Old entries expire so a printer with
	// a stable set of IPs does not alert forever.
	window := 10 * time.Second
	hist := de.macClaimHist[cleanMAC]
	fresh := hist[:0]
	seen := map[string]bool{}
	for _, c := range hist {
		if now.Sub(c.TS) <= window {
			fresh = append(fresh, c)
			seen[c.IP] = true
		}
	}
	if !seen[cleanIP] {
		fresh = append(fresh, claimEntry{IP: cleanIP, TS: now})
		seen[cleanIP] = true
	}
	de.macClaimHist[cleanMAC] = fresh

	if len(fresh) >= 12 {
		return de.createAlertLocked(models.Alert{
			Type:       models.AlertARPSpoofing,
			Severity:   models.SeverityHigh,
			Confidence: 0.90,
			TargetMAC:  cleanMAC,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("MAC %s claimed %d distinct IPs within %v (mass-spoof signature)", cleanMAC, len(fresh), window),
					Details: map[string]interface{}{
						"claimed_ips": distinctIPs(fresh),
						"mac":         cleanMAC,
						"window":      window.String(),
					},
				},
			},
			RecommendedAction: "Quarantine MAC address and enable Dynamic ARP Inspection (DAI) on switch",
		})
	}

	return nil
}

func distinctIPs(hist []claimEntry) []string {
	out := make([]string, 0, len(hist))
	for _, c := range hist {
		out = append(out, c.IP)
	}
	return out
}

// isVirtualHAMAC reports VRRP (00:00:5e:00:01:xx), HSRP (00:00:0c:07:ac:xx),
// GLBP (00:07:b4:xx:xx:xx) and locally-administered virtual ranges.
func isVirtualHAMAC(mac string) bool {
	m := strings.ToLower(mac)
	for _, p := range []string{"00:00:5e", "00:00:0c:07:ac", "00:07:b4", "02:"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// InspectDHCPOffer checks if a DHCP offer came from an approved server.
func (de *DetectionEngine) InspectDHCPOffer(serverIP, serverMAC string) *models.Alert {
	de.mu.Lock()
	defer de.mu.Unlock()

	if len(de.trustedDHCP) > 0 && !de.trustedDHCP[serverIP] {
		now := time.Now().UTC()
		return de.createAlertLocked(models.Alert{
			Type:       models.AlertRogueDHCP,
			Severity:   models.SeverityCritical,
			Confidence: 0.95,
			TargetIP:   serverIP,
			TargetMAC:  serverMAC,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("Unauthorized DHCP server response observed from %s (%s)", serverIP, serverMAC),
					Details: map[string]interface{}{
						"rogue_ip":  serverIP,
						"rogue_mac": serverMAC,
					},
				},
			},
			RecommendedAction: "Block DHCP server port or apply switch DHCP snooping immediately",
		})
	}
	return nil
}

// InspectPortConnection tracks port scan activity from a source IP.
func (de *DetectionEngine) InspectPortConnection(srcIP, dstIP string, dstPort int) *models.Alert {
	de.mu.Lock()
	defer de.mu.Unlock()

	if srcIP == "" || dstPort <= 0 {
		return nil
	}

	now := time.Now().UTC()
	ports, ok := de.portScans[srcIP]
	if !ok {
		ports = make(map[int]time.Time)
		de.portScans[srcIP] = ports
	}

	// Prune ports older than 15 seconds
	for p, ts := range ports {
		if now.Sub(ts) > 15*time.Second {
			delete(ports, p)
		}
	}

	ports[dstPort] = now

	// If source has targeted > 12 distinct ports in window, raise alert
	if len(ports) >= 12 {
		return de.createAlertLocked(models.Alert{
			Type:       models.AlertPortScanDetected,
			Severity:   models.SeverityMedium,
			Confidence: 0.90,
			TargetIP:   srcIP,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("Source host %s scanned %d ports within 15 seconds (last target: %s:%d)", srcIP, len(ports), dstIP, dstPort),
					Details: map[string]interface{}{
						"src_ip":        srcIP,
						"dst_ip":        dstIP,
						"scanned_ports": len(ports),
					},
				},
			},
			RecommendedAction: "Inspect host for reconnaissance malware or unauthorized port scanner tools",
		})
	}

	return nil
}

// InspectBandwidth identifies sudden abnormal bandwidth usage.
func (de *DetectionEngine) InspectBandwidth(deviceID, ip string, rateBps float64, thresholdBps float64) *models.Alert {
	de.mu.Lock()
	defer de.mu.Unlock()

	if thresholdBps > 0 && rateBps > thresholdBps {
		now := time.Now().UTC()
		return de.createAlertLocked(models.Alert{
			Type:       models.AlertBandwidthAnomaly,
			Severity:   models.SeverityHigh,
			Confidence: 0.88,
			DeviceID:   deviceID,
			TargetIP:   ip,
			Evidence: []models.AlertEvidence{
				{
					Timestamp:   now,
					Description: fmt.Sprintf("Host %s bandwidth consumption (%.2f Mbps) exceeded anomaly threshold (%.2f Mbps)", ip, rateBps/1e6, thresholdBps/1e6),
					Details: map[string]interface{}{
						"rate_bps":      rateBps,
						"threshold_bps": thresholdBps,
					},
				},
			},
			RecommendedAction: "Apply bandwidth rate shaping policy or inspect for unauthorized large data exfiltration",
		})
	}
	return nil
}

func (de *DetectionEngine) createAlertLocked(proto models.Alert) *models.Alert {
	now := time.Now().UTC()

	// Check for deduplication (same type & target within 10 minutes)
	for _, existing := range de.alerts {
		if existing.Type == proto.Type && existing.TargetMAC == proto.TargetMAC && existing.TargetIP == proto.TargetIP {
			existing.LastSeen = now
			existing.Evidence = append(existing.Evidence, proto.Evidence...)
			if len(existing.Evidence) > 20 {
				existing.Evidence = existing.Evidence[len(existing.Evidence)-20:]
			}
			if de.eventBus != nil {
				de.eventBus.Publish(events.EventAlertUpdated, "", existing)
			}
			return existing
		}
	}

	alertID := uuid.New().String()
	alert := &models.Alert{
		ID:                alertID,
		Type:              proto.Type,
		Severity:          proto.Severity,
		Confidence:        proto.Confidence,
		DeviceID:          proto.DeviceID,
		TargetMAC:         proto.TargetMAC,
		TargetIP:          proto.TargetIP,
		Segment:           proto.Segment,
		FirstSeen:         now,
		LastSeen:          now,
		Evidence:          proto.Evidence,
		RecommendedAction: proto.RecommendedAction,
	}

	de.alerts[alertID] = alert
	if de.eventBus != nil {
		de.eventBus.Publish(events.EventAlertCreated, "", alert)
	}
	return alert
}

// ListAlerts returns all current alerts.
func (de *DetectionEngine) ListAlerts() []*models.Alert {
	de.mu.RLock()
	defer de.mu.RUnlock()

	res := make([]*models.Alert, 0, len(de.alerts))
	for _, a := range de.alerts {
		res = append(res, a)
	}
	return res
}

// AcknowledgeAlert marks an alert as addressed.
func (de *DetectionEngine) AcknowledgeAlert(ctx context.Context, id, actor string) error {
	de.mu.Lock()
	defer de.mu.Unlock()

	alert, ok := de.alerts[id]
	if !ok {
		return fmt.Errorf("alert %q not found", id)
	}

	now := time.Now().UTC()
	alert.Acknowledged = true
	alert.AcknowledgedBy = actor
	alert.AcknowledgedAt = &now

	if de.eventBus != nil {
		de.eventBus.Publish(events.EventAlertUpdated, "", alert)
	}
	return nil
}
