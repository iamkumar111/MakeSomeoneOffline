//go:build windows

package adapters

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/open-netcut/open-netcut/pkg/discovery"
)

// Minimal dynamic Npcap binding. wpcap.dll is loaded at runtime so the
// control plane builds and runs without Npcap installed; live cuts simply
// report unavailable until the driver/DLL is present. No CGO, no SDK needed
// at build time.

// pcap structs mirror the C layout (64-bit pointers first, then uint32).
type pcapSockaddr struct {
	family uint16
	data   [14]byte
}

type pcapAddr struct {
	next      *pcapAddr
	addr      *pcapSockaddr
	netmask   *pcapSockaddr
	broadaddr *pcapSockaddr
	dstaddr   *pcapSockaddr
}

type pcapIf struct {
	next        *pcapIf
	name        *byte
	description *byte
	addresses   *pcapAddr
	flags       uint32
}

var (
	npcapLoadOnce   sync.Once
	npcapLoadError  error
	procFindalldevs *syscall.Proc
	procFreealldevs *syscall.Proc
	procOpenLive    *syscall.Proc
	procSendpacket  *syscall.Proc
	procClose       *syscall.Proc
)

// Restrict the library AND dependencies to the installed system directories.
// Bare-name loading could execute a wpcap.dll/Packet.dll planted beside the EXE.
func loadNpcap() error {
	npcapLoadOnce.Do(func() {
		kernel := syscall.NewLazyDLL("kernel32.dll")
		var directory [32768]uint16
		n, _, err := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
		if n == 0 || n >= uintptr(len(directory)) {
			npcapLoadError = fmt.Errorf("resolve Windows system directory: %v", err)
			return
		}
		systemDir := syscall.UTF16ToString(directory[:n])
		loader := kernel.NewProc("LoadLibraryExW")
		for _, path := range []string{filepath.Join(systemDir, "Npcap", "wpcap.dll"), filepath.Join(systemDir, "wpcap.dll")} {
			wide, err := syscall.UTF16PtrFromString(path)
			if err != nil {
				npcapLoadError = err
				return
			}
			// LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32.
			handle, _, loadErr := loader.Call(uintptr(unsafe.Pointer(wide)), 0, 0x100|0x800)
			if handle == 0 {
				npcapLoadError = fmt.Errorf("load %s: %v", path, loadErr)
				continue
			}
			dll := &syscall.DLL{Name: path, Handle: syscall.Handle(handle)}
			bindings := []struct {
				name   string
				target **syscall.Proc
			}{
				{"pcap_findalldevs", &procFindalldevs}, {"pcap_freealldevs", &procFreealldevs},
				{"pcap_open_live", &procOpenLive}, {"pcap_sendpacket", &procSendpacket}, {"pcap_close", &procClose},
			}
			for _, binding := range bindings {
				proc, err := dll.FindProc(binding.name)
				if err != nil {
					npcapLoadError = err
					_ = dll.Release()
					return
				}
				*binding.target = proc
			}
			npcapLoadError = nil
			return
		}
	})
	return npcapLoadError
}

// npcapAvailable reports whether wpcap.dll loads.
func npcapAvailable() bool {
	return loadNpcap() == nil
}

func cString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var b []byte
	for i := 0; i < 512; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func cErr(buf *[256]byte) string {
	s := string(buf[:])
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// npcapIPv4Devices lists capture devices that have an IPv4 address,
// as (device name, ip) pairs.
func npcapIPv4Devices() ([][2]string, error) {
	if err := loadNpcap(); err != nil {
		return nil, fmt.Errorf("wpcap.dll not available: %w", err)
	}
	var all *pcapIf
	var errbuf [256]byte
	ret, _, _ := procFindalldevs.Call(
		uintptr(unsafe.Pointer(&all)),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", cErr(&errbuf))
	}
	defer procFreealldevs.Call(uintptr(unsafe.Pointer(all)))
	var out [][2]string
	for dev := all; dev != nil; dev = dev.next {
		name := cString(dev.name)
		if name == "" {
			continue
		}
		for a := dev.addresses; a != nil; a = a.next {
			if a.addr == nil || a.addr.family != 2 { // AF_INET
				continue
			}
			ip := net.IP(append([]byte(nil), a.addr.data[2:6]...))
			if ip == nil {
				continue
			}
			out = append(out, [2]string{name, ip.String()})
		}
	}
	return out, nil
}

// npcapOpen opens a device for raw frame injection.
func npcapOpen(device string) (uintptr, error) {
	if err := loadNpcap(); err != nil {
		return 0, fmt.Errorf("wpcap.dll not available: %w", err)
	}
	cName := append([]byte(device), 0)
	var errbuf [256]byte
	ret, _, _ := procOpenLive.Call(
		uintptr(unsafe.Pointer(&cName[0])),
		uintptr(65536), // snaplen
		uintptr(1),     // promiscuous
		uintptr(100),   // read timeout ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if ret == 0 {
		return 0, fmt.Errorf("pcap_open_live %s: %s", device, cErr(&errbuf))
	}
	return ret, nil
}

// npcapSend injects one raw Ethernet frame.
func npcapSend(handle uintptr, frame []byte) error {
	if len(frame) == 0 {
		return fmt.Errorf("empty frame")
	}
	ret, _, _ := procSendpacket.Call(
		handle,
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)),
	)
	if ret != 0 {
		return fmt.Errorf("pcap_sendpacket failed")
	}
	return nil
}

func npcapClose(handle uintptr) {
	if handle != 0 {
		procClose.Call(handle)
	}
}

// probeGatewayIP best-effort resolves the default gateway (empty on failure;
// selection then falls back to first-private-IP heuristics).
func probeGatewayIP() string {
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

// windowsNDPAddrs returns cached IPv6 addresses for a MAC (link-locals
// first) from `netsh interface ipv6 show neighbors`.
func windowsNDPAddrs(ctx context.Context, mac net.HardwareAddr) []net.IP {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "netsh", "interface", "ipv6", "show", "neighbors").CombinedOutput()
	if err != nil {
		return nil
	}
	return linkLocalsFirst(discovery.ParseNetshIPv6Neighbors(string(out))[strings.ToLower(mac.String())])
}

// ProbeWindowsInjection validates the whole Npcap path without touching the
// network: enumerate devices, select the LAN interface, resolve our MAC,
// open the capture handle, close it. Any struct-layout or calling-convention
// bug in this binding surfaces here instead of mid-quarantine.
func ProbeWindowsInjection() (device, ip, mac string, err error) {
	devices, err := npcapIPv4Devices()
	if err != nil {
		return "", "", "", err
	}
	locals, err := localIPv4Interfaces()
	if err != nil {
		return "", "", "", err
	}
	devName, devIP, hostMAC, err := selectLocalDevice(devices, locals, probeGatewayIP(), "")
	if err != nil {
		return "", "", "", err
	}
	handle, err := npcapOpen(devName)
	if err != nil {
		return "", "", "", err
	}
	npcapClose(handle)
	return devName, devIP, hostMAC.String(), nil
}
