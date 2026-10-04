package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

func parseServerAndArgs() (string, []string) {
	server := "http://localhost:8080"
	if env := os.Getenv("OPEN_NETCUT_SERVER"); env != "" {
		server = env
	}

	var cleanArgs []string
	rawArgs := os.Args[1:]
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		if arg == "-server" || arg == "--server" || arg == "-url" || arg == "--url" {
			if i+1 < len(rawArgs) {
				server = rawArgs[i+1]
				i++
				continue
			}
		} else if strings.HasPrefix(arg, "-server=") || strings.HasPrefix(arg, "--server=") {
			server = strings.SplitN(arg, "=", 2)[1]
			continue
		} else if strings.HasPrefix(arg, "-url=") || strings.HasPrefix(arg, "--url=") {
			server = strings.SplitN(arg, "=", 2)[1]
			continue
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}

	return strings.TrimRight(server, "/"), cleanArgs
}

func main() {
	serverURL, args := parseServerAndArgs()
	if len(args) == 0 {
		printUsage()
		return
	}

	command := args[0]
	client := &http.Client{Timeout: 10 * time.Second}

	switch command {
	case "status", "stats":
		cmdStats(client, serverURL)
	case "devices", "ls":
		cmdDevices(client, serverURL)
	case "alerts":
		cmdAlerts(client, serverURL)
	case "cut", "quarantine":
		if len(args) < 2 {
			fmt.Println("Error: target IP or device ID required. Usage: netcut-cli cut <ip|id> [--adapter <name>] [--ttl <seconds>]")
			os.Exit(1)
		}
		cmdQuarantine(client, serverURL, args[1], args[2:])
	case "restore", "uncut":
		if len(args) < 2 {
			fmt.Println("Error: target IP or device ID required. Usage: netcut-cli restore <ip|id>")
			os.Exit(1)
		}
		cmdRestore(client, serverURL, args[1])
	case "limit":
		if len(args) < 2 {
			fmt.Println("Error: target IP or device ID required. Usage: netcut-cli limit <ip|id> [download_bps] [upload_bps]")
			os.Exit(1)
		}
		cmdLimit(client, serverURL, args[1], args[2:])
	default:
		fmt.Printf("Unknown command %q\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Open-NetCut Administrator CLI")
	fmt.Println("\nUsage: netcut-cli [--server http://localhost:8080] <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  status, stats      View system health, device counts, and threat level")
	fmt.Println("  devices, ls        List all discovered LAN endpoints")
	fmt.Println("  alerts             List active security alerts and evidence")
	fmt.Println("  cut <ip|id>        Apply immediate quarantine on a device [--adapter <name>] [--ttl <seconds>]")
	fmt.Println("  restore <ip|id>    Lift quarantine and restore network access")
	fmt.Println("  limit <ip|id>      Apply bandwidth shaping (rate limit)")
}

func cmdStats(client *http.Client, baseURL string) {
	resp, err := client.Get(baseURL + "/api/v1/stats")
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&stats)

	fmt.Println("--- Open-NetCut System Status ---")
	for k, v := range stats {
		fmt.Printf("  %-22s: %v\n", strings.ReplaceAll(k, "_", " "), v)
	}
}

func cmdDevices(client *http.Client, baseURL string) {
	resp, err := client.Get(baseURL + "/api/v1/devices")
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var devices []models.Device
	_ = json.NewDecoder(resp.Body).Decode(&devices)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tIP ADDRESS\tMAC ADDRESS\tNAME\tVENDOR\tTRUST\tRISK\tDEVICE ID")
	for _, d := range devices {
		status := "ONLINE"
		if !d.IsOnline {
			status = "OFFLINE"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			status, d.PrimaryIP, d.PrimaryMAC, d.DisplayName, d.Vendor, d.TrustState, d.RiskScore, d.ID[:8])
	}
	w.Flush()
}

func cmdAlerts(client *http.Client, baseURL string) {
	resp, err := client.Get(baseURL + "/api/v1/alerts")
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var alerts []models.Alert
	_ = json.NewDecoder(resp.Body).Decode(&alerts)

	if len(alerts) == 0 {
		fmt.Println("No active security threats detected.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tTYPE\tTARGET IP\tTARGET MAC\tDESCRIPTION")
	for _, a := range alerts {
		desc := ""
		if len(a.Evidence) > 0 {
			desc = a.Evidence[0].Description
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(a.Severity)), a.Type, a.TargetIP, a.TargetMAC, desc)
	}
	w.Flush()
}

func findDeviceID(client *http.Client, baseURL, identifier string) (string, error) {
	if len(identifier) == 36 && strings.Contains(identifier, "-") {
		return identifier, nil // Already full UUID
	}

	resp, err := client.Get(baseURL + "/api/v1/devices")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var devices []models.Device
	_ = json.NewDecoder(resp.Body).Decode(&devices)

	for _, d := range devices {
		if d.PrimaryIP == identifier || strings.EqualFold(d.PrimaryMAC, identifier) || strings.HasPrefix(d.ID, identifier) {
			return d.ID, nil
		}
	}

	return "", fmt.Errorf("device %q not found", identifier)
}

func cmdQuarantine(client *http.Client, baseURL, target string, extraArgs []string) {
	devID, err := findDeviceID(client, baseURL, target)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	adapter := ""
	ttlSec := 900
	dryRun := false

	for i := 0; i < len(extraArgs); i++ {
		arg := extraArgs[i]
		if arg == "--dry-run" || arg == "-dry-run" {
			dryRun = true
		} else if strings.HasPrefix(arg, "--adapter=") || strings.HasPrefix(arg, "-adapter=") {
			adapter = strings.SplitN(arg, "=", 2)[1]
		} else if (arg == "--adapter" || arg == "-adapter" || arg == "-a") && i+1 < len(extraArgs) {
			adapter = extraArgs[i+1]
			i++
		} else if strings.HasPrefix(arg, "--ttl=") || strings.HasPrefix(arg, "-ttl=") {
			_, _ = fmt.Sscanf(strings.SplitN(arg, "=", 2)[1], "%d", &ttlSec)
		} else if (arg == "--ttl" || arg == "-ttl" || arg == "-t") && i+1 < len(extraArgs) {
			_, _ = fmt.Sscanf(extraArgs[i+1], "%d", &ttlSec)
			i++
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"adapter":     adapter,
		"ttl_seconds": ttlSec,
		"dry_run":     dryRun,
	})

	resp, err := client.Post(fmt.Sprintf("%s/api/v1/devices/%s/quarantine", baseURL, devID), "application/json", bytes.NewReader(payload))
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed: %s\n", string(body))
		return
	}

	var enf models.Enforcement
	_ = json.Unmarshal(body, &enf)
	adapterUsed := enf.Adapter
	if adapterUsed == "" {
		adapterUsed = "system"
	}

	fmt.Printf("Success: Quarantined device %s (Enforcement applied via %s, TTL: %d min)\n", target, adapterUsed, ttlSec/60)
}

func cmdRestore(client *http.Client, baseURL, target string) {
	devID, err := findDeviceID(client, baseURL, target)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/devices/%s/quarantine", baseURL, devID), nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed: HTTP %d\n", resp.StatusCode)
		return
	}

	fmt.Printf("Success: Quarantine lifted for device %s\n", target)
}

func cmdLimit(client *http.Client, baseURL, target string, extraArgs []string) {
	devID, err := findDeviceID(client, baseURL, target)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	down := uint64(2000000) // Default 2 Mbps
	up := uint64(1000000)   // Default 1 Mbps

	payload, _ := json.Marshal(map[string]interface{}{
		"adapter":      "mock_simulator",
		"download_bps": down,
		"upload_bps":   up,
		"ttl_seconds":  3600,
		"dry_run":      false,
	})

	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/devices/%s/rate-limit", baseURL, devID), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed: HTTP %d\n", resp.StatusCode)
		return
	}

	fmt.Printf("Success: Rate limit applied to %s (2 Mbps down / 1 Mbps up)\n", target)
}
