package discovery

import (
	"encoding/binary"
	"net"
	"strings"
)

// dhcpSnoopResult is the parsed identity from one DHCP client packet.
func parseDHCPPacket(frame []byte) (mac, reqIP, hostname, serverIP string, ok bool) { // Ethernet(14) + IPv4(>=20, proto UDP) + UDP(8, dport 67/68) + BOOTP(>=240).
	if len(frame) < 14+20+8+240 {
		return "", "", "", "", false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return "", "", "", "", false
	}
	ihl := int(frame[14]&0x0F) * 4
	if ihl < 20 || len(frame) < 14+ihl+8+240 {
		return "", "", "", "", false
	}
	ip := frame[14 : 14+ihl]
	if ip[9] != 17 { // UDP
		return "", "", "", "", false
	}
	udp := frame[14+ihl:]
	sport := binary.BigEndian.Uint16(udp[0:2])
	dport := binary.BigEndian.Uint16(udp[2:4])
	if !((sport == 68 && dport == 67) || (sport == 67 && dport == 68)) {
		return "", "", "", "", false
	}
	bootp := udp[8:]
	if len(bootp) < 240 {
		return "", "", "", "", false
	}
	if bootp[0] != 1 && bootp[0] != 2 { // BOOTREQUEST or BOOTREPLY
		return "", "", "", "", false
	}
	hwType, hwLen := bootp[1], int(bootp[2])
	if hwType != 1 || hwLen != 6 { // Ethernet
		return "", "", "", "", false
	}
	chaddr := net.HardwareAddr(bootp[28:34])
	if chaddr[0]&0x01 != 0 {
		return "", "", "", "", false // multicast/broadcast MAC
	}
	if binary.BigEndian.Uint32(bootp[236:240]) != 0x63825363 {
		return "", "", "", "", false // bad magic cookie
	}
	opts := bootp[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 { // END
			break
		}
		if code == 0 { // PAD
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		ln := int(opts[i+1])
		if i+2+ln > len(opts) {
			break
		}
		val := opts[i+2 : i+2+ln]
		switch code {
		case 12: // Host Name
			hostname = sanitizeDHCPString(val)
		case 50: // Requested IP
			if len(val) == 4 {
				reqIP = net.IP(val).String()
			}
		case 54: // Server Identifier
			if len(val) == 4 {
				serverIP = net.IP(val).String()
			}
		}
		i += 2 + ln
	}
	// Fall back to the BOOTP yiaddr (offered/acked address) when the client
	// didn't include option 50 (e.g. DISCOVER without request, renewals).
	if reqIP == "" {
		if yiaddr := net.IP(bootp[16:20]); yiaddr.To4() != nil && !yiaddr.IsUnspecified() {
			reqIP = yiaddr.String()
		}
	}
	mac = chaddr.String()
	if hostname == "" && reqIP == "" {
		return "", "", "", "", false
	}
	return mac, reqIP, hostname, serverIP, true
}

// sanitizeDHCPString keeps plausible hostnames, dropping binary garbage.
func sanitizeDHCPString(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			sb.WriteByte(c)
		} else if c == 0 {
			break
		} else {
			return ""
		}
	}
	s := sb.String()
	if len(s) < 2 || len(s) > 63 {
		return ""
	}
	return s
}
