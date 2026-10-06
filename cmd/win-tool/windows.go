//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type doctorReport struct {
	Admin           bool   `json:"admin"`
	NpcapService    string `json:"npcap_service"`
	WinDivertStatus string `json:"windivert_status"`
	Interface       string `json:"interface"`
	IPv4            string `json:"ipv4"`
	Gateway         string `json:"gateway"`
	Ready           bool   `json:"ready_for_live_cut"`
}

func runDoctor() {
	report := doctorReport{
		Admin:           isAdmin(),
		NpcapService:    serviceState("npcap"),
		WinDivertStatus: serviceState("windivert"),
	}
	iface, ip := primaryIPv4()
	report.Interface = iface
	report.IPv4 = ip
	report.Gateway = defaultGateway()
	report.Ready = report.Admin && report.NpcapService == "running" && report.Gateway != ""
	emitJSON(report)
	if !report.Ready {
		os.Exit(2)
	}
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

func primaryIPv4() (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					return iface.Name, ip.String()
				}
			}
		}
	}
	return "", ""
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
	client := &http.Client{Timeout: 30 * time.Second}
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
	fmt.Printf("Cut applied via windows_sidehost (TTL %ds). Verify the victim, then heal with: win-tool heal %s\n", ttl, target)
}

func runHeal(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: win-tool heal <ip|mac|id>")
		os.Exit(1)
	}
	client := &http.Client{Timeout: 30 * time.Second}
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
