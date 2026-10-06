package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/detection"
	"github.com/open-netcut/open-netcut/pkg/discovery"
	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
	"github.com/open-netcut/open-netcut/pkg/notify"
	"github.com/open-netcut/open-netcut/pkg/policy"
	"github.com/open-netcut/open-netcut/pkg/server"
	"github.com/open-netcut/open-netcut/pkg/store"
	"github.com/open-netcut/open-netcut/pkg/traffic"
)

// syncEnginesFromStore restores policies, audit, schedules, webhooks and
// operator device state (manual names, trust) saved by a previous run.
func syncEnginesFromStore(st *store.MemoryStore, pe *policy.PolicyEngine, sm *policy.ScheduleManager, ad *notify.AlertDispatcher, fusion *discovery.IdentityFusionEngine, fc *policy.FreezeController) {
	ctx := context.Background()
	if pols, err := st.ListPolicies(ctx); err == nil && len(pols) > 0 {
		pe.RestorePolicies(pols)
	}
	if logs, err := st.ListAuditLogs(ctx, 1000); err == nil && len(logs) > 0 {
		pe.RestoreAudit(logs)
	}
	for _, sched := range st.GetSchedules() {
		if sched != nil && sched.ID != "" {
			sched.Active = true
			sm.AddSchedule(sched)
		}
	}
	for _, ep := range st.GetWebhooks() {
		if ep != nil && ep.ID != "" {
			ad.RegisterEndpoint(ep)
		}
	}
	if devs, err := st.ListDevices(ctx, ""); err == nil && len(devs) > 0 {
		fusion.RestoreDevices(devs)
	}
	if fc != nil {
		fc.Restore(st.GetFreeze())
		if st.GetFreeze().Active {
			log.Printf("Restored active freeze latch (reason: %q) — newcomers will be cut", st.GetFreeze().Reason)
		}
	}
}

// syncStoreFromEngines stages live engine state into the store for snapshots.
// Live enforcements are deliberately NOT persisted: dropping them here would
// resurrect kernel rules nobody owns after a restart (see startup reconcile).
func syncStoreFromEngines(st *store.MemoryStore, pe *policy.PolicyEngine, sm *policy.ScheduleManager, ad *notify.AlertDispatcher, fusion *discovery.IdentityFusionEngine, fc *policy.FreezeController) {
	ctx := context.Background()
	for _, p := range pe.SnapshotPolicies() {
		_ = st.SavePolicy(ctx, p)
	}
	for _, l := range pe.SnapshotAudit() {
		_ = st.SaveAuditLog(ctx, &l)
	}
	for _, d := range fusion.SnapshotDevices() {
		_ = st.SaveDevice(ctx, d)
	}
	st.SetSchedules(sm.ListSchedules())
	st.SetWebhooks(ad.ListEndpoints())
	if fc != nil {
		st.SetFreeze(fc.Snapshot())
	}
}

// reconcileQuarantineChains clears our nftables quarantine chains on startup.
// Live enforcements die with the process (TTL timers, ARP poison loops), but
// kernel drop rules would otherwise block devices forever with no record.
func reconcileQuarantineChains(nft *adapters.LinuxNFTablesAdapter) {
	if nft == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nft.FlushQuarantineChains(ctx); err != nil {
		log.Printf("Warning: quarantine chain reconcile failed: %v", err)
		return
	}
	log.Printf("Startup reconcile: cleared stale quarantine rules (fresh enforcement state)")
}

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	siteID := flag.String("site", "default", "Site identifier")
	enableScanner := flag.Bool("scanner", true, "Enable local ARP/procfs network scanner")
	dbPath := flag.String("db", "", "Path to persistent database storage (optional)")
	flag.Parse()

	envPort := os.Getenv("PORT")
	if envPort != "" {
		*port = envPort
	}

	log.Printf("Starting Open-NetCut Control Plane [site: %s] on :%s ...", *siteID, *port)
	if *dbPath != "" {
		log.Printf("Storage database path: %s", *dbPath)
	}

	// 1. Initialize Event Bus
	eventBus := events.NewEventBus()

	// 2. Discover default gateway to seed allowlist and ARP detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gwIP, gwMAC, err := discovery.GetDefaultGateway(ctx)
	if err == nil {
		log.Printf("Authoritative Gateway identified: IP=%s, MAC=%s", gwIP, gwMAC)
	} else {
		log.Printf("Notice: Default gateway not auto-detected: %v (can be configured via API)", err)
	}

	// 3. Setup Management Allowlist
	allowlist := models.Allowlist{
		GatewayIPs:    []string{gwIP},
		GatewayMACs:   []string{gwMAC},
		DNSIPs:        []string{"1.1.1.1", "8.8.8.8", gwIP},
		AdminIPs:      []string{"127.0.0.1"},
		ControllerIPs: []string{"127.0.0.1"},
	}

	// 4. Setup Enforcement Adapters
	registry := adapters.NewAdapterRegistry()
	mockAdapter := adapters.NewMemoryMockAdapter("mock_simulator")
	registry.Register(mockAdapter)
	adapters.RegisterPlatformAdapters(registry)

	nftAdapter := adapters.NewLinuxNFTablesAdapter("open_netcut", "quarantine")
	if nftAdapter.IsAvailable(ctx) {
		registry.Register(nftAdapter)
		log.Printf("Linux nftables adapter registered successfully")
	}
	tcIface := os.Getenv("TC_IFACE")
	if tcIface == "" {
		tcIface = "eth0"
	}
	tcAdapter := adapters.NewLinuxTCAdapter(tcIface)
	if tcAdapter.IsAvailable(ctx) {
		registry.Register(tcAdapter)
		log.Printf("Linux tc adapter registered on %s", tcIface)
	}

	for _, a := range registry.List() {
		log.Printf("Adapter: %s caps=%v", a.Name(), a.Capabilities())
	}

	if gwIP != "" && gwMAC != "" {
		// L2 ARP adapter is opt-in only (ARP spoofing is not default enforcement).
		if os.Getenv("ENABLE_L2_ARP") == "1" {
			l2Adapter, err := adapters.NewL2ARPAdapter(gwIP, gwMAC, nil, nftAdapter)
			if err == nil && l2Adapter.IsAvailable(ctx) {
				registry.Register(l2Adapter)
				log.Printf("L2 ARP adapter registered (opt-in ENABLE_L2_ARP=1)")
			} else if err != nil {
				log.Printf("Notice: L2 ARP adapter could not be initialized: %v", err)
			}
		} else {
			log.Printf("L2 ARP cut disabled (set ENABLE_L2_ARP=1 to allow side-host LAN quarantine — own networks only, disruptive by design)")
		}
	}

	// 5. Initialize Core Engines
	fusionEngine := discovery.NewIdentityFusionEngine(*siteID, eventBus)
	detectionEngine := detection.NewDetectionEngine(detection.KnownGateway{
		IP:  gwIP,
		MAC: gwMAC,
	}, eventBus)
	// Seed trusted DHCP / IPv6 routers from env (comma-separated).
	for _, ip := range strings.Split(os.Getenv("TRUSTED_DHCP"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			detectionEngine.SetTrustedDHCPServer(ip)
		}
	}
	if gwIP != "" {
		detectionEngine.SetTrustedDHCPServer(gwIP)
	}
	for _, mac := range strings.Split(os.Getenv("TRUSTED_IPV6_ROUTERS"), ",") {
		if mac = strings.TrimSpace(mac); mac != "" {
			detectionEngine.SetTrustedIPv6Router(mac)
		}
	}
	policyEngine := policy.NewPolicyEngine(registry, eventBus, allowlist)
	// Scheduler + auto-remediation + webhook dispatcher (were dead code before).
	schedManager := policy.NewScheduleManager(policyEngine)
	defer schedManager.Stop()
	schedManager.SetResolver(func(deviceID string) *models.Device {
		dev, _ := fusionEngine.GetDevice(deviceID)
		return dev
	})
	// Policy evaluation loop: makes WHEN/THEN rules actually fire.
	policyEval := policy.NewEvaluator(policyEngine, fusionEngine.ListDevices, 60*time.Second)
	defer policyEval.Stop()
	autoRem := policy.NewAutoRemediationEngine(policyEngine, eventBus, "", 10*time.Minute)
	defer autoRem.Stop()
	if os.Getenv("DISABLE_AUTO_REM remediation") != "" || os.Getenv("DISABLE_AUTO_REMEDIATION") == "1" {
		autoRem.SetEnabled(false)
	}
	dispatcher := notify.NewAlertDispatcher(eventBus)
	defer dispatcher.Stop()
	// Freeze latch: while ON, newly discovered devices are cut automatically.
	freezeCtrl := policy.NewFreezeController(policyEngine, eventBus,
		fusionEngine.ListDevices,
		func(id string, state models.TrustState) error { return fusionEngine.SetTrustState(id, state) },
		policyEngine.IsProtected,
	)
	defer freezeCtrl.Stop()
	memStore := store.NewMemoryStore()
	// JSON-file persistence via -db flag: atomic tmp+rename, .bak fallback,
	// periodic autosave + final save on shutdown. No MySQL/Postgres needed.
	// Engine state (policies, audit, schedules, webhooks) is synced into the
	// snapshot; live enforcements are NOT restored (see startup reconcile).
	if *dbPath != "" {
		if err := memStore.LoadFromFile(*dbPath); err != nil {
			log.Printf("Notice: could not load store %s: %v", *dbPath, err)
		} else {
			log.Printf("Loaded persisted store from %s", *dbPath)
		}
		syncEnginesFromStore(memStore, policyEngine, schedManager, dispatcher, fusionEngine, freezeCtrl)
		stopAutosave := memStore.StartAutoSave(*dbPath, 10*time.Second, func() {
			syncStoreFromEngines(memStore, policyEngine, schedManager, dispatcher, fusionEngine, freezeCtrl)
		})
		defer stopAutosave()
		defer func() {
			syncStoreFromEngines(memStore, policyEngine, schedManager, dispatcher, fusionEngine, freezeCtrl)
			if err := memStore.SaveToFile(*dbPath); err != nil {
				log.Printf("Warning: store save failed: %v", err)
			} else {
				log.Printf("Store snapshot saved to %s (+ .bak)", *dbPath)
			}
		}()
	}
	telemetryEngine := traffic.NewTelemetryEngine(*siteID, eventBus)
	telemetryEngine.StartRateCalculator(ctx, 3*time.Second)
	defer telemetryEngine.Stop()
	// Per-IP byte accounting: feeds TopTalkers (was all-zeros before —
	// nothing ever called RecordFlow). nftables per-IP counters are primary
	// (no conntrack module needed); conntrack is the fallback. Both degrade
	// to interface totals when unavailable.
	conntrackPoller := traffic.NewConntrackPoller(telemetryEngine, 5*time.Second)
	go conntrackPoller.Start(ctx)
	defer conntrackPoller.Stop()
	knownLANIPs := func() []string {
		devs := fusionEngine.ListDevices()
		ips := make([]string, 0, len(devs))
		for _, d := range devs {
			if strings.TrimSpace(d.PrimaryIP) != "" {
				ips = append(ips, d.PrimaryIP)
			}
		}
		return ips
	}
	nftPoller := traffic.NewNftAccountingPoller(telemetryEngine, knownLANIPs, 5*time.Second)
	go nftPoller.Start(ctx)
	defer nftPoller.Stop()

	// Publish integration online event for any realtime listeners.
	eventBus.Publish(events.EventIntegrationOnline, *siteID, map[string]string{"adapters": "registered"})

	// 6. Start Local Discovery if enabled
	if *enableScanner {
		scanner := discovery.NewNetworkScanner(fusionEngine, nil)
		scanner.Start(ctx, 10*time.Second)
		defer scanner.Stop()

		serviceListener := discovery.NewServiceDiscoveryListener(fusionEngine)
		serviceListener.Start(ctx)
		defer serviceListener.Stop()

		dhcpWatcher := discovery.NewDHCPLeaseWatcher(fusionEngine, nil)
		dhcpWatcher.Start(ctx, 15*time.Second)

		dhcpSnoop := discovery.NewDHCPSnooper(fusionEngine)
		dhcpSnoop.Start(ctx)
		defer dhcpSnoop.Stop()

		ipv6Scanner := discovery.NewIPv6Scanner(fusionEngine)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			ipv6Scanner.ScanIPv6Neighbors(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ipv6Scanner.ScanIPv6Neighbors(ctx)
				}
			}
		}()
		log.Printf("Local discovery started: ARP/procfs + mDNS/SSDP/UPnP + DHCP leases/snoop + IPv6 NDP")
	}

	// 7. Subscribe detection and telemetry engines to incoming device observations via EventBus
	obsSub := eventBus.Subscribe(100)
	go func() {
		for evt := range obsSub {
			if evt.Type == events.EventDeviceSeen || evt.Type == events.EventDeviceUpdated {
				if dev, ok := evt.Data.(*models.Device); ok {
					telemetryEngine.RegisterDeviceBinding(dev.ID, dev.PrimaryIP, dev.PrimaryMAC)
					detectionEngine.AnalyzeObservation(models.Observation{
						Timestamp: dev.LastSeen,
						Source:    "discovery_fusion",
						MAC:       dev.PrimaryMAC,
						IP:        dev.PrimaryIP,
					})
				}
			}
		}
	}()

	// 8. Start HTTP / WebSocket Server
	// Startup reconcile BEFORE serving: drop rules from a previous run have
	// no owning enforcement anymore; leaving them would block devices with
	// no record and no TTL to release them.
	reconcileQuarantineChains(nftAdapter)
	srv := server.NewServer(fusionEngine, detectionEngine, policyEngine, telemetryEngine, eventBus, memStore, *siteID,
		server.WithScheduler(schedManager),
		server.WithAutoRemediation(autoRem),
		server.WithAlertDispatcher(dispatcher),
		server.WithFreezeController(freezeCtrl),
	)
	httpServer := &http.Server{
		Addr:         ":" + *port,
		Handler:      srv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("Open-NetCut Control Plane ready: http://localhost:%s", *port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Printf("Shutting down Open-NetCut...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	policyEngine.Stop()
	fusionEngine.Stop()
	log.Printf("Shutdown complete.")
}
