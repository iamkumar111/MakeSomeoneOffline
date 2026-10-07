package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-netcut/open-netcut/pkg/models"
)

// isCameraDevice reports whether a device looks like an IP camera/NVR from
// fingerprinting (HTTP banner, RTSP port) or advertised services.
func isCameraDevice(dev *models.Device) bool {
	if dev == nil {
		return false
	}
	if dt, ok := dev.Metadata["device_type"].(string); ok {
		l := strings.ToLower(dt)
		if strings.Contains(l, "camera") || strings.Contains(l, "nvr") {
			return true
		}
	}
	if _, ok := dev.Metadata["rtsp_open"]; ok {
		return true
	}
	for _, s := range dev.Services {
		l := strings.ToLower(s.Name)
		if strings.Contains(l, "camera") || strings.Contains(l, "nvr") || strings.Contains(l, "onvif") {
			return true
		}
	}
	return false
}

func (s *Server) handleCameras(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := []map[string]interface{}{}
	for _, dev := range s.fusionEngine.ListDevices() {
		if !isCameraDevice(dev) {
			continue
		}
		_, rtsp := dev.Metadata["rtsp_open"]
		out = append(out, map[string]interface{}{
			"id":           dev.ID,
			"display_name": dev.DisplayName,
			"primary_ip":   dev.PrimaryIP,
			"primary_mac":  dev.PrimaryMAC,
			"vendor":       dev.Vendor,
			"is_online":    dev.IsOnline,
			"rtsp_open":    rtsp,
			"banner":       dev.Metadata["http_banner"],
			"web_url":      fmt.Sprintf("http://%s/", dev.PrimaryIP),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// cameraSnapshotPaths are well-known ANONYMOUS snapshot endpoints. No
// credentials are ever tried: a path either serves a public still or it is
// skipped. Auth-protected cameras correctly report "not found" here.
var cameraSnapshotPaths = []string{
	"/snapshot.jpg",
	"/cgi-bin/snapshot.cgi",
	"/tmpfs/auto.jpg",
	"/image.jpg",
	"/snap.jpg",
	"/jpg/image.jpg",
	"/axis-cgi/jpg/image.cgi",
	"/ISAPI/Streaming/channels/101/picture",
}

func (s *Server) handleCameraDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/cameras/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		http.Error(w, "Camera ID required", http.StatusBadRequest)
		return
	}
	dev, ok := s.fusionEngine.GetDevice(id)
	if !ok {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}
	if len(parts) == 2 && parts[1] == "snapshot" && r.Method == http.MethodPost {
		s.probeCameraSnapshot(w, r, dev)
		return
	}
	if len(parts) == 2 && parts[1] == "image" && r.Method == http.MethodGet {
		s.proxyCameraImage(w, r, dev)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

// probeCameraSnapshot tries anonymous snapshot paths against the camera's
// port 80 and returns the first that serves a real image.
func (s *Server) probeCameraSnapshot(w http.ResponseWriter, r *http.Request, dev *models.Device) {
	if dev.PrimaryIP == "" {
		http.Error(w, "device has no IP", http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	base := fmt.Sprintf("http://%s", dev.PrimaryIP)
	for _, p := range cameraSnapshotPaths {
		ct, n, ok := trySnapshotURL(client, r.Context(), base+p)
		if !ok {
			continue
		}
		s.policyEngine.Audit(actorFromRequest(r), "camera_snapshot_found", "device", dev.ID, fmt.Sprintf("path=%s type=%s", p, ct), "success")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"found":        true,
			"path":         p,
			"content_type": ct,
			"bytes":        n,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"found": false})
}

// trySnapshotURL fetches one candidate snapshot URL. It reports ok only for
// HTTP 200 image bodies that pass magic-byte sniffing, so login pages and
// empty responses never count. baseURL carries scheme+host(+port) for tests.
func trySnapshotURL(client *http.Client, ctx context.Context, rawURL string) (contentType string, n int, ok bool) {
	// Copy rather than mutate the caller's client. Never follow a camera redirect
	// to another host (including local services or a metadata endpoint).
	guarded := *client
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, false
	}
	resp, err := guarded.Do(req)
	if err != nil {
		return "", 0, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	ct := resp.Header.Get("Content-Type")
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", 0, false
	}
	if !strings.HasPrefix(ct, "image/") || len(body) < 1024 || !looksLikeImage(body) {
		return "", 0, false
	}
	return ct, len(body), true
}

// proxyCameraImage streams a snapshot or MJPEG stream through the backend so
// the UI works without mixed-content/CORS issues. The target is pinned to the
// device's own IP (SSRF guard): either a device-relative ?path= or a full
// ?src= URL whose host matches the device.
func (s *Server) proxyCameraImage(w http.ResponseWriter, r *http.Request, dev *models.Device) {
	q := r.URL.Query()
	target := ""
	if p := q.Get("path"); p != "" {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		if dev.PrimaryIP == "" {
			http.Error(w, "device has no IP", http.StatusBadRequest)
			return
		}
		target = fmt.Sprintf("http://%s%s", dev.PrimaryIP, p)
	} else if src := q.Get("src"); src != "" {
		u, err := url.Parse(src)
		if err != nil || u.Scheme != "http" || u.Host == "" {
			http.Error(w, "src must be an http(s) URL", http.StatusBadRequest)
			return
		}
		host := u.Hostname()
		allowed := host == dev.PrimaryIP
		if !allowed {
			for _, a := range dev.Addresses {
				if a.IP == host {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			http.Error(w, "src host must be the device itself", http.StatusBadRequest)
			return
		}
		target = src
	} else {
		http.Error(w, "path or src query required", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }} // streams run until disconnect
	if q.Get("src") == "" {
		client.Timeout = 8 * time.Second // single snapshots must be quick
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("camera fetch failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("camera returned %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(ct), "image/") && !strings.HasPrefix(strings.ToLower(ct), "multipart/x-mixed-replace") {
		http.Error(w, "camera response is not an image or MJPEG stream", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	if f, ok := w.(http.Flusher); ok {
		// Cap proxied streams so a runaway MJPEG feed can't fill memory;
		// browsers re-request on each refresh tick anyway.
		_, _ = io.CopyN(w, resp.Body, 20<<20)
		f.Flush()
	} else {
		_, _ = io.Copy(w, resp.Body)
	}
}

// looksLikeImage sniffs common still-image magic bytes.
func looksLikeImage(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	if b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF {
		return true // JPEG
	}
	if bytes.Equal(b[:4], []byte{0x89, 'P', 'N', 'G'}) {
		return true
	}
	if bytes.Equal(b[:4], []byte{'G', 'I', 'F', '8'}) {
		return true
	}
	if bytes.Equal(b[:2], []byte{'B', 'M'}) {
		return true
	}
	return false
}
