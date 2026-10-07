# macOS: Initial Version

Available: dashboard, LAN IPv4 discovery, native gateway detection, and dry-run
previews. Live quarantine, release of real cuts, packet monitoring, and bandwidth
shaping are not implemented for macOS. Live enforcement requests return an error.

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
folder. Run from the project root. No sudo is needed for this initial version.
Open [localhost:8080](http://localhost:8080); no token or login is needed locally.

## Verify

1. Check your gateway with `/sbin/route -n get default` and neighbors with
   `/usr/sbin/arp -an`. Incomplete neighbors are intentionally excluded.
2. Allow any macOS local-network permission prompt. Wait for discovery and
   compare a test device's IP/MAC with the ARP table.
3. Select the device, choose the mock simulator, and enable **Dry Run**.
   Apply a 60-second preview. The device should stay online and the live cut
   count should remain zero. Restore the preview or let its TTL expire.
4. A request with Dry Run off must report that macOS live quarantine is unavailable.

## Troubleshooting

- **No devices:** check local-network permissions, Wi-Fi/Ethernet, VPN routes,
  and guest-network isolation. Devices outside the local IPv4 neighbor cache
  may not appear. IPv6-only discovery is not implemented in this version.
- **Blank page:** build the dashboard and start from the project root.
- **App blocked:** use your organization's approved signing/development process.
  Downloaded releases need signing/notarization before general distribution.
- **Remote access:** set `NETCUT_API_TOKEN` and explicitly use `-listen 0.0.0.0`.
  Put remote access behind an HTTPS proxy. Remote clients require the token;
  local access requires a loopback Host and peer with no forwarding headers.

Both macOS architectures are cross-compiled on Windows; native runtime and LAN
verification on a Mac are still required before calling this version tested.
