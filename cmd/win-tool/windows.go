//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
	"github.com/open-netcut/open-netcut/pkg/apiclient"
)

type doctorReport struct {
	Admin             bool     `json:"admin"`
	NpcapService      string   `json:"npcap_service"`
	WinDivertStatus   string   `json:"windivert_status"`
	Interface         string   `json:"interface"`
	IPv4              string   `json:"ipv4"`
	Gateway           string   `json:"gateway"`
	GatewayMAC        string   `json:"gateway_mac"`
	ForwardingEnabled *bool    `json:"ip_forwarding_enabled"`
	ProbeOK           bool     `json:"npcap_probe_ok"`
	Blockers          []string `json:"blockers"`
	Ready             bool     `json:"ready_for_live_cut"`
}

func runDoctor() {
	report := doctorReport{
		Admin:           isAdmin(),
		NpcapService:    serviceState("npcap"),
		WinDivertStatus: serviceState("windivert"),
		Blockers:        []string{},
	}
	if !report.Admin {
		report.Blockers = append(report.Blockers, "Run PowerShell as Administrator for live quarantine.")
	}
	forwarding, err := adapters.WindowsForwardingState()
	if err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	} else {
		report.ForwardingEnabled = &forwarding
		if forwarding {
			report.Blockers = append(report.Blockers, "IP forwarding is enabled; side-host quarantine requires it OFF. See WINDOWS_SETUP_AND_TEST_GUIDE.md.")
		}
	}
	dev, ip, _, err := adapters.ProbeWindowsInjection()
	report.Interface = dev
	report.IPv4 = ip
	report.ProbeOK = err == nil
	if err != nil {
		report.Blockers = append(report.Blockers, "Npcap probe: "+err.Error())
	}
	report.Gateway = defaultGateway()
	report.GatewayMAC = gatewayMAC(report.Gateway)
	// Gateway MAC must already be in the ARP cache: Apply refuses when it
	// cannot resolve it (ping the gateway once if this is empty).
	if report.Gateway == "" {
		report.Blockers = append(report.Blockers, "No IPv4 default gateway found; check the LAN connection and VPN routes.")
	} else if report.GatewayMAC == "" {
		report.Blockers = append(report.Blockers, "Gateway MAC is absent from the ARP cache; ping the gateway once, then retry doctor.")
	}
	// Successful opening of Npcap is authoritative; its service may start on demand.
	report.Ready = len(report.Blockers) == 0
	emitJSON(report)
	if !report.Ready {
		os.Exit(2)
	}
}

func gatewayMAC(gateway string) string {
	if gateway == "" {
		return ""
	}
	var buf bytes.Buffer
	cmd := exec.Command("arp", "-a")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return ""
	}
	for _, n := range ParseWindowsArp(buf.String()) {
		if n.IPAddress == gateway && n.MACAddress != "" {
			return n.MACAddress
		}
	}
	return ""
}

// runProbe exercises the real Npcap path (enumerate → select → open → close)
// without sending anything. Run this BEFORE any live cut: it catches binding,
// driver, and interface-selection bugs with zero network impact.
func runProbe() {
	dev, ip, mac, err := adapters.ProbeWindowsInjection()
	out := map[string]interface{}{
		"probe": "npcap-open-close", "device": dev, "ip": ip, "mac": mac,
	}
	if err != nil {
		out["ok"] = false
		out["error"] = err.Error()
		emitJSON(out)
		os.Exit(1)
	}
	out["ok"] = true
	emitJSON(out)
}

func isAdmin() bool {
	// `net session` succeeds for elevated administrators and fails otherwise.
	return exec.Command("net", "session").Run() == nil
}

func serviceState(name string) string {
	out, err := exec.Command("sc", "query", name).CombinedOutput()
	if err != nil {
		return "not-installed"
	}
	text := strings.ToUpper(string(out))
	switch {
	case strings.Contains(text, "RUNNING"):
		return "running"
	case strings.Contains(text, "STOPPED"):
		return "stopped"
	default:
		return "unknown"
	}
}

func defaultGateway() string {
	out, err := exec.Command("route", "print", "-4").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2]
		}
	}
	return ""
}

func apiBase() string {
	if v := strings.TrimSpace(os.Getenv("OPEN_NETCUT_SERVER")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

type apiDevice struct {
	ID         string `json:"id"`
	PrimaryIP  string `json:"primary_ip"`
	PrimaryMAC string `json:"primary_mac"`
}

func resolveDeviceID(client *http.Client, target string) (string, error) {
	target = strings.TrimSpace(target)
	resp, err := client.Get(apiBase() + "/api/v1/devices")
	if err != nil {
		return "", fmt.Errorf("control plane not reachable at %s: %v", apiBase(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("device lookup rejected by control plane (HTTP %d)", resp.StatusCode)
	}
	var devices []apiDevice
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return "", err
	}
	norm := strings.ToLower(strings.ReplaceAll(target, "-", ":"))
	for _, d := range devices {
		if d.ID == target ||
			strings.ToLower(d.PrimaryIP) == strings.ToLower(target) ||
			strings.ToLower(strings.ReplaceAll(d.PrimaryMAC, "-", ":")) == norm {
			return d.ID, nil
		}
	}
	return "", fmt.Errorf("device %q not found — run scan first and wait a few seconds", target)
}

func runCut(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: win-tool cut <ip|mac|id> [--ttl seconds] [--dry-run]")
		os.Exit(1)
	}
	target, ttl, dryRun := args[0], 900, false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dryRun = true
		case "--ttl":
			if i+1 >= len(args) {
				fmt.Println("Usage: win-tool cut <ip|mac|id> [--ttl seconds] [--dry-run]")
				os.Exit(1)
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Println("ttl must be positive seconds")
				os.Exit(1)
			}
			ttl = v
			i++
		}
	}
	client := apiclient.New(30 * time.Second)
	id, err := resolveDeviceID(client, target)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	body, _ := json.Marshal(map[string]interface{}{
		"adapter": "windows_sidehost", "ttl_seconds": ttl, "dry_run": dryRun,
	})
	resp, err := client.Post(apiBase()+"/api/v1/devices/"+id+"/quarantine", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var res map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode >= 300 {
		fmt.Printf("Cut rejected (%d): %v\n", resp.StatusCode, res)
		os.Exit(1)
	}
	if st, _ := res["status"].(string); st == "already_cut" {
		fmt.Println("Already cut — existing enforcement returned, no duplicate loop started.")
		return
	}
	if dryRun {
		fmt.Printf("Dry-run recorded (TTL %ds); no traffic blocked.\n", ttl)
		return
	}
	fmt.Printf("Cut applied via windows_sidehost (TTL %ds). Verify the victim, then heal with: win-tool heal %s\n", ttl, target)
}

func runHeal(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: win-tool heal <ip|mac|id>")
		os.Exit(1)
	}
	client := apiclient.New(30 * time.Second)
	id, err := resolveDeviceID(client, args[0])
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	req, _ := http.NewRequest(http.MethodDelete, apiBase()+"/api/v1/devices/"+id+"/quarantine", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Printf("Heal rejected (%d)\n", resp.StatusCode)
		os.Exit(1)
	}
	fmt.Println("Quarantine lifted — healing frames sent, caches restore within seconds.")
}

func runScan(args []string) {
	asJSON := len(args) > 0 && args[0] == "--json"
	var buf bytes.Buffer
	cmd := exec.Command("arp", "-a")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		fmt.Printf("arp -a failed: %v\n", err)
		os.Exit(1)
	}
	neighbors := ParseWindowsArp(buf.String())
	if asJSON {
		emitJSON(neighbors)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP ADDRESS\tMAC ADDRESS\tTYPE")
	for _, n := range neighbors {
		fmt.Fprintf(w, "%s\t%s\t%s\n", n.IPAddress, n.MACAddress, n.Type)
	}
	w.Flush()
}
