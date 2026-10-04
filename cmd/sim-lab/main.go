package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

func main() {
	controlPlaneURL := flag.String("url", "http://localhost:8080", "Control Plane API base URL")
	scenario := flag.String("scenario", "normal", "Simulation scenario: 'normal', 'arp-spoof', 'rogue-dhcp', 'all'")
	flag.Parse()

	log.Printf("Starting Open-NetCut LAN Lab Simulator [%s] targeting %s ...", *scenario, *controlPlaneURL)
	client := &http.Client{Timeout: 5 * time.Second}

	devices := []models.Observation{
		{
			Timestamp: time.Now().UTC(),
			Source:    "arp",
			IP:        "192.168.1.1",
			MAC:       "00:11:22:33:44:55",
			Hostname:  "Core-Gateway-Router",
		},
		{
			Timestamp: time.Now().UTC(),
			Source:    "dhcp",
			IP:        "192.168.1.102",
			MAC:       "3c:06:30:44:55:66", // Apple
			Hostname:  "MacBook-Pro-M3",
		},
		{
			Timestamp: time.Now().UTC(),
			Source:    "arp",
			IP:        "192.168.1.108",
			MAC:       "b8:27:eb:12:34:56", // Raspberry Pi
			Hostname:  "HomeAssistant-Pi",
		},
		{
			Timestamp: time.Now().UTC(),
			Source:    "ssdp",
			IP:        "192.168.1.115",
			MAC:       "40:b4:cd:77:88:99", // Samsung TV
			Hostname:  "Samsung-QLED-TV",
			Attributes: map[string]interface{}{
				"service_name":  "urn:schemas-upnp-org:device:MediaRenderer:1",
				"service_port":  8001,
				"service_proto": "tcp",
			},
		},
		{
			Timestamp: time.Now().UTC(),
			Source:    "mdns",
			IP:        "192.168.1.140",
			MAC:       "da:a1:19:bb:cc:dd", // Private / Randomized MAC
			Hostname:  "iPhone-Guest",
		},
	}

	// Post normal devices
	for _, dev := range devices {
		postObservation(client, *controlPlaneURL, dev)
		time.Sleep(200 * time.Millisecond)
	}
	log.Printf("Injected 5 realistic LAN endpoints into Open-NetCut inventory.")

	if *scenario == "arp-spoof" || *scenario == "all" {
		time.Sleep(1 * time.Second)
		log.Printf("Injecting ARP Spoofing / Gateway Impersonation Attack Scenario...")
		attacker := models.Observation{
			Timestamp: time.Now().UTC(),
			Source:    "arp",
			IP:        "192.168.1.1",       // Spoofs default gateway
			MAC:       "de:ad:be:ef:13:37", // Attacker MAC
		}
		postObservation(client, *controlPlaneURL, attacker)
		log.Printf("Attacker MAC de:ad:be:ef:13:37 claiming Gateway IP 192.168.1.1 broadcasted.")
	}

	log.Printf("Simulation complete. Check the web dashboard at %s to view devices and alerts.", *controlPlaneURL)
}

func postObservation(client *http.Client, baseURL string, obs models.Observation) {
	// Post as observation or event
	data, _ := json.Marshal(obs)
	resp, err := client.Post(baseURL+"/api/v1/observations", "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Printf("Notice: could not POST to /api/v1/observations: %v\n", err)
		return
	}
	_ = resp.Body.Close()
}
