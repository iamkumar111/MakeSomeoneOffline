//go:build windows

package adapters

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
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
	wpcapDLL        = syscall.NewLazyDLL("wpcap.dll")
	procFindalldevs = wpcapDLL.NewProc("pcap_findalldevs")
	procFreealldevs = wpcapDLL.NewProc("pcap_freealldevs")
	procOpenLive    = wpcapDLL.NewProc("pcap_open_live")
	procSendpacket  = wpcapDLL.NewProc("pcap_sendpacket")
	procClose       = wpcapDLL.NewProc("pcap_close")
)

// npcapAvailable reports whether wpcap.dll loads.
func npcapAvailable() bool {
	return wpcapDLL.Load() == nil
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
	if err := wpcapDLL.Load(); err != nil {
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
	if err := wpcapDLL.Load(); err != nil {
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

// selectDevice picks the capture device: NETCUT_WIN_IFACE override (NPF name
// substring or IPv4), else the first private-LAN IPv4 device.
func selectDevice(devices [][2]string) (name, ip string, err error) {
	if len(devices) == 0 {
		return "", "", fmt.Errorf("no Npcap devices with IPv4 addresses found")
	}
	if want := strings.TrimSpace(strings.ToLower(os.Getenv("NETCUT_WIN_IFACE"))); want != "" {
		for _, d := range devices {
			if strings.Contains(strings.ToLower(d[0]), want) || strings.ToLower(d[1]) == want {
				return d[0], d[1], nil
			}
		}
		return "", "", fmt.Errorf("NETCUT_WIN_IFACE %q matched no Npcap device", want)
	}
	for _, d := range devices {
		if ip := net.ParseIP(d[1]); ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
			return d[0], d[1], nil
		}
	}
	for _, d := range devices {
		if ip := net.ParseIP(d[1]); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return d[0], d[1], nil
		}
	}
	return devices[0][0], devices[0][1], nil
}
