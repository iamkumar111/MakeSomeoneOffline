package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HostFingerprint stores discovered OS, device type, computer name, and banners.
type HostFingerprint struct {
	Hostname   string
	OS         string
	DeviceType string
	Vendor     string
	Metadata   map[string]interface{}
}

// FingerprintHost attempts active OS and hostname resolution via NetBIOS (UDP 137), HTTP (TCP 80), SMB (TCP 445), and Apple sync (TCP 62078).
func FingerprintHost(ctx context.Context, ip string) HostFingerprint {
	fp := HostFingerprint{
		Metadata: make(map[string]interface{}),
	}

	// 1. Query NetBIOS Node Status (UDP port 137) - Reveals Windows & Mac computer names
	if nbName, isWin, isMac := queryNetBIOS(ip); nbName != "" {
		fp.Hostname = nbName
		fp.Metadata["netbios_name"] = nbName
		if isMac {
			fp.OS = "macOS"
			fp.DeviceType = "Apple MacBook"
			fp.Vendor = "Apple, Inc."
		} else if isWin {
			fp.OS = "Windows 10/11"
			fp.DeviceType = "Windows PC"
			fp.Vendor = "Microsoft Windows"
		}
		return fp
	}

	// 2. Query HTTP banner (TCP port 80 / 8080) - Identifies IP Cameras, NVRs, Routers
	if httpType, banner, pageTitle := probeHTTP(ctx, ip); httpType != "" {
		fp.DeviceType = httpType
		fp.Metadata["http_banner"] = banner
		if strings.Contains(httpType, "Camera") {
			fp.OS = "Embedded Linux"
			fp.Hostname = "IP-Camera-NVR"
			fp.Vendor = "Hikvision / Xiongmai"
		}
		if fp.Hostname == "" && pageTitle != "" {
			fp.Hostname = pageTitle
			fp.Metadata["http_title"] = pageTitle
		}
		return fp
	}

	// 2b. RTSP port open without (recognized) web UI: still a strong camera
	// signal — most IP cameras/NVRs listen on TCP 554.
	if isPortOpen(ip, 554, 150*time.Millisecond) {
		fp.OS = "Embedded Linux"
		fp.DeviceType = "IP Camera / NVR"
		fp.Metadata["rtsp_open"] = true
		return fp
	}

	// 3. Check SMB (TCP port 445) - Windows / Samba sharing
	if isPortOpen(ip, 445, 100*time.Millisecond) {
		fp.OS = "Windows"
		fp.DeviceType = "Windows PC"
		fp.Metadata["smb_active"] = true
		return fp
	}

	// 4. Check Apple lockdownd (TCP port 62078)
	if isPortOpen(ip, 62078, 100*time.Millisecond) {
		fp.OS = "iOS"
		fp.DeviceType = "Apple iPhone / iPad"
		fp.Vendor = "Apple, Inc."
		return fp
	}

	return fp
}

func queryNetBIOS(ip string) (name string, isWindows bool, isMac bool) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), 200*time.Millisecond)
	if err != nil {
		return "", false, false
	}
	defer conn.Close()

	// Standard NetBIOS Node Status Request
	req := []byte{
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}

	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		return "", false, false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return "", false, false
	}

	numNames := int(buf[56])
	for i := 0; i < numNames; i++ {
		offset := 57 + (i * 18)
		if offset+15 > n {
			break
		}
		raw := string(buf[offset : offset+15])
		clean := strings.TrimSpace(raw)
		if clean == "" || clean == "WORKGROUP" {
			continue
		}

		upper := strings.ToUpper(clean)
		if strings.Contains(upper, "MACBOOK") || strings.Contains(upper, "MAC-") {
			return clean, false, true
		}
		if strings.HasPrefix(upper, "DESKTOP-") || strings.HasPrefix(upper, "LAPTOP-") || strings.Contains(upper, "PC") {
			return clean, true, false
		}
		if name == "" {
			name = clean
			isWindows = true
		}
	}

	return name, isWindows, isMac
}

func probeHTTP(ctx context.Context, ip string) (deviceType, banner, pageTitle string) {
	client := http.Client{
		Timeout: 250 * time.Millisecond,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/", ip), nil)
	if err != nil {
		return "", "", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", ""
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	bodyStr := string(body)

	if strings.Contains(server, "APPWebs") || strings.Contains(bodyStr, "login.html") || strings.Contains(bodyStr, "doc/images") {
		return "IP Camera / NVR", "APPWebs / Video Surveillance", ""
	}
	if strings.Contains(bodyStr, "Router") || strings.Contains(server, "micro_httpd") {
		return "Network Router", server, extractHTMLTitle(bodyStr)
	}

	return "Web Service", server, extractHTMLTitle(bodyStr)
}

// junkPageTitles are placeholder titles carrying no identity.
var junkPageTitles = map[string]bool{
	"login": true, "log in": true, "home": true, "index": true,
	"index of /": true, "router": true, "web": true, "admin": true,
	"setup": true, "configuration": true, "status": true, "main": true,
	"default": true, "welcome": true, "dashboard": true, "untitled": true,
}

// extractHTMLTitle pulls a usable device name from a page <title>.
// Returns "" for missing, junk, or IP-like titles.
func extractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(body[start+len("<title>") : start+end])
	// Strip common decorations: "RT-AC68U - Login" -> "RT-AC68U".
	for _, sep := range []string{" - ", " | ", " :: ", " – ", " — "} {
		if i := strings.Index(title, sep); i > 0 {
			title = strings.TrimSpace(title[:i])
		}
	}
	if len(title) < 3 || len(title) > 64 {
		return ""
	}
	if junkPageTitles[strings.ToLower(title)] {
		return ""
	}
	if net.ParseIP(title) != nil {
		return ""
	}
	return title
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
