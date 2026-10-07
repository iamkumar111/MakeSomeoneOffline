package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// This is the direct Windows helper entry point. Discovery/diagnostics that
// need Windows commands live in windows.go. Portable parsing helpers live in
// arpparse.go so they can be unit-tested everywhere.
func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	if runtime.GOOS != "windows" {
		fmt.Println("win-tool runs on Windows only.")
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "doctor":
		runDoctor()
	case "probe":
		runProbe()
	case "scan":
		runScan(os.Args[2:])
	case "cut":
		runCut(os.Args[2:])
	case "heal":
		runHeal(os.Args[2:])
	default:
		fmt.Printf("Unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Open-NetCut direct Windows helper")
	fmt.Println("\nUsage: win-tool <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  doctor             Check admin, drivers, interface, and gateway readiness")
	fmt.Println("  probe              Safe Npcap open/close test (sends nothing) — run before live cuts")
	fmt.Println("  scan [--json]      List neighbors from the local ARP table")
	fmt.Println("  cut <ip|mac|id> [--ttl seconds] [--dry-run]")
	fmt.Println("                     Cut a device via the local control plane (windows_sidehost)")
	fmt.Println("  heal <ip|mac|id>   Lift quarantine via the local control plane")
}

func emitJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
