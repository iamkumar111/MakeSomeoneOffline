# macOS: Setup and BPF Quarantine

For retained logs and unresponsive buttons, see
[Troubleshooting for all platforms](TROUBLESHOOTING.md).

Discovery/dashboard/previews work without root. Experimental live quarantine
uses native BPF (`macos_sidehost`), saved-mapping restoration and TTL.
No Npcap, libpcap installation or CGO is needed. Rate limiting is unavailable.

## Install and build

Download [Go 1.25 or newer](https://go.dev/dl/) and
[Node.js LTS 22.12 or newer](https://nodejs.org/en/download).
Choose **arm64** for Apple Silicon or **amd64/x64** for Intel.

From the project folder:

```sh
sh scripts/build-macos.sh
./bin/open-netcut-macos-arm64 -port 8080 -db ./netcut.json
```

Intel Macs: replace `arm64` with `amd64`. Keep `web/dist` beside the `bin`
folder. Run from the project root. No sudo is needed for discovery/previews.
Open [localhost:8080](http://localhost:8080); no token or login is needed locally.

## Enable and verify live BPF quarantine

Use a separate test device on your own LAN. Stop the ordinary server first.
Gateway and target must be on the same IPv4 subnet and physical `enN` interface.
Ethernet is preferable for testing; Wi-Fi drivers may reject or rewrite frames.

1. Turn off Internet Sharing/routing. Check both settings and native neighbors:

   ```sh
   sysctl net.inet.ip.forwarding net.inet6.ip6.forwarding
   /sbin/route -n get default
   /usr/sbin/arp -an
   ```

   Both forwarding values must be `0`. Unknown state is rejected. Do not use
   this side-host adapter on a Mac acting as a gateway.
2. Probe permissions/interface configuration; **no packets are sent**:

   ```sh
   sudo env ENABLE_MACOS_L2_ARP=1 ./bin/mac-tool-arm64 probe
   ```

   `ready_for_injection: true` means BPF opened/configured. It does not prove
   driver injection or isolation. Optional `-target 192.168.1.24` checks a
   specific device's route/cache; use its actual IP.
3. Start the server with explicit opt-in and privileges:

   ```sh
   sudo env ENABLE_MACOS_L2_ARP=1 ./bin/open-netcut-macos-arm64 -port 8080 -db ./netcut.json
   ```

   Keep it running. Allow macOS local-network permission if prompted.
4. Select the test device → Quarantine Device → manually select
   **macOS Side-Host — BPF ARP quarantine**. It is never auto-selected.
5. Test Dry Run first: device stays online; live count stays zero.
6. Disable Dry Run, select **1 minute (test)**, apply, and check fresh IPv4/IPv6
   connections on the target. Restore and verify recovery; repeat and let TTL
   expire. Restoration takes about five seconds.

IPv6 NDP is best effort, using genuine neighbor mappings known before injection.
Applied status does not prove complete isolation. Native Mac/LAN testing is required.

## Troubleshooting

- **No devices:** check local-network permissions, Wi-Fi/Ethernet, VPN routes,
  and guest-network isolation. Devices outside the local IPv4 neighbor cache
  may not appear. IPv6-only discovery is not implemented in this version.
- **Blank page:** build the dashboard and start from the project root.
- **Offline adapter:** check opt-in, server root privileges and both forwarding
  settings. Elevating only the probe does not elevate the server.
- **Gateway/target MAC missing or changed:** inspect ARP, ping the known gateway
  once to populate its cache, then refresh discovery. Changed target MACs are rejected.
- **Wrong interface / VPN:** default and target routes must use the same physical
  `enN`. Remote routed subnets, tunnels, bridges and non-Ethernet BPF types are rejected.
- **BPF busy/denied:** inspect permissions and capture applications. Busy
  descriptors are skipped; actual open/ioctl errors appear in the probe.
- **Injection/restore failure:** save Audit and `logs/control-plane.log*`.
  Incomplete restoration keeps a visible Restore/TTL owner. A partial apply
  can return an error and still require Restore; do not repeat quarantine.
- **Stopping:** Ctrl+C attempts restoration. Forced termination cannot guarantee
  healing; multiple cuts may exceed the shutdown budget. Inspect logs and target recovery.
- **Root-created database/logs:** reuse the same privileges, or select writable
  `-db`/`-log-dir` paths when switching back to preview mode.
- **App blocked:** use your organization's approved signing/development process.
  Downloaded releases need signing/notarization before general distribution.
- **Remote access:** set `NETCUT_API_TOKEN` in the privileged server environment
  and explicitly use `-listen 0.0.0.0`.
  Put remote access behind an HTTPS proxy. Remote clients require the token;
  local access requires a loopback Host and peer with no forwarding headers.

Both macOS architectures are cross-compiled on Windows; native runtime and LAN
verification on a Mac are still required before calling this version tested.
