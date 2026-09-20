package discovery

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

var (
	loadOUIsOnce sync.Once
	systemOUIs   = make(map[string]string)
)

func initSystemOUIs() {
	paths := []string{
		"/usr/share/nmap/nmap-mac-prefixes",
		"/usr/share/ieee-data/oui.txt",
		"/var/lib/ieee-data/oui.txt",
	}

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// nmap format: "00000C Cisco Systems"
			fields := strings.Fields(line)
			if len(fields) >= 2 && len(fields[0]) == 6 {
				prefix := strings.ToLower(fields[0][:2] + ":" + fields[0][2:4] + ":" + fields[0][4:6])
				vendor := strings.Join(fields[1:], " ")
				if _, exists := systemOUIs[prefix]; !exists {
					systemOUIs[prefix] = vendor
				}
			}
		}
		if len(systemOUIs) > 0 {
			break
		}
	}
}

// OUIDatabase maps 24-bit OUI prefixes (e.g., "00:50:56") to hardware manufacturers.
var standardOUIs = map[string]string{
	"00:e0:22": "Analog Devices",
	"00:e0:27": "DUX, Inc.",
	"00:e0:4c": "Realtek Semiconductor",
	"10:e7:c6": "Hewlett Packard",
	"dc:fb:48": "Intel Corporate",
	"f4:27:56": "Dasan Network Solutions",
	"8c:ec:4b": "Dell",
	"00:50:56": "VMware, Inc.",
	"00:0c:29": "VMware, Inc.",
	"00:15:5d": "Microsoft Corporation (Hyper-V)",
	"52:54:00": "QEMU / KVM Virtual Machine",
	"b8:27:eb": "Raspberry Pi Foundation",
	"dc:a6:32": "Raspberry Pi Trading Ltd",
	"e4:5f:01": "Raspberry Pi Trading Ltd",
	"28:cd:c1": "Raspberry Pi Trading Ltd",
	"00:1a:11": "Google, Inc.",
	"3c:5a:b4": "Google, Inc.",
	"f4:f5:d8": "Google, Inc.",
	"d8:6c:63": "Google, Inc.",
	"f0:18:98": "Apple, Inc.",
	"ac:de:48": "Apple, Inc.",
	"bc:d0:74": "Apple, Inc.",
	"3c:06:30": "Apple, Inc.",
	"70:3a:cb": "Apple, Inc.",
	"88:66:a5": "Apple, Inc.",
	"f4:34:f0": "Apple, Inc.",
	"00:1e:c2": "Apple, Inc.",
	"a4:83:e7": "Apple, Inc.",
	"40:b4:cd": "Samsung Electronics",
	"50:01:d9": "Samsung Electronics",
	"94:65:2d": "Samsung Electronics",
	"cc:07:ab": "Samsung Electronics",
	"00:1b:21": "Intel Corporate",
	"00:21:6a": "Intel Corporate",
	"68:05:ca": "Intel Corporate",
	"8c:16:45": "Intel Corporate",
	"00:14:22": "Dell Inc.",
	"18:66:da": "Dell Inc.",
	"f8:db:88": "Dell Inc.",
	"00:25:b3": "HP Inc.",
	"3c:d9:2b": "HP Inc.",
	"9c:b6:54": "HP Inc.",
	"00:26:86": "Cisco Systems",
	"00:27:0d": "Cisco Systems",
	"70:10:5c": "Cisco Systems",
	"24:a0:74": "Espressif Systems (ESP8266/ESP32)",
	"30:ae:a4": "Espressif Systems (ESP8266/ESP32)",
	"84:0d:8e": "Espressif Systems (ESP8266/ESP32)",
	"a0:20:a6": "Espressif Systems (ESP8266/ESP32)",
	"c4:4f:33": "Espressif Systems (ESP8266/ESP32)",
	"ec:fa:bc": "Espressif Systems (ESP8266/ESP32)",
	"50:c7:bf": "TP-Link Corporation",
	"60:32:b1": "TP-Link Corporation",
	"c0:06:c3": "TP-Link Corporation",
	"e8:48:b8": "TP-Link Corporation",
	"00:0c:43": "Ralink Technology (MediaTek)",
	"74:ac:b9": "Ubiquiti Networks",
	"b4:fb:e4": "Ubiquiti Networks",
	"f0:9f:c2": "Ubiquiti Networks",
	"48:8f:5a": "MikroTik",
	"64:d1:54": "MikroTik",
	"78:9a:18": "MikroTik",
	"b8:69:f4": "MikroTik",
	"c4:ad:34": "MikroTik",
	"00:11:32": "Synology Incorporated",
	"00:08:9b": "QNAP Systems, Inc.",
	"00:17:88": "Philips Lighting (Hue)",
	"ec:b5:fa": "Philips Lighting (Hue)",
	"64:16:66": "Amazon Technologies Inc.",
	"44:65:0d": "Amazon Technologies Inc.",
	"ac:63:be": "Amazon Technologies Inc.",
	"fc:65:de": "Amazon Technologies Inc.",
}

// LookupVendor returns the hardware manufacturer for a MAC address, or "Unknown Vendor".
func LookupVendor(mac string) string {
	clean := strings.ToLower(strings.TrimSpace(mac))
	clean = strings.ReplaceAll(clean, "-", ":")
	parts := strings.Split(clean, ":")
	if len(parts) >= 3 {
		prefix := strings.Join(parts[0:3], ":")
		if vendor, ok := standardOUIs[prefix]; ok {
			return vendor
		}

		loadOUIsOnce.Do(initSystemOUIs)
		if vendor, ok := systemOUIs[prefix]; ok {
			return vendor
		}
	}

	// Check for locally administered address (randomized MAC)
	// Byte 0 bit 1 set => locally administered (e.g. x2, x6, xA, xE)
	if len(parts) > 0 && len(parts[0]) == 2 {
		firstByte := parts[0]
		if len(firstByte) == 2 {
			secondNibble := firstByte[1]
			if secondNibble == '2' || secondNibble == '6' || secondNibble == 'a' || secondNibble == 'e' {
				return "Private / Randomized MAC (Mobile)"
			}
		}
	}

	return "Unknown Vendor"
}
