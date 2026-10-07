# Security fixes and validation

This review covers the HTTP control plane, quarantine/release adapters, camera
proxy, and frontend status handling. It is a focused code review, not a claim
that every vulnerability or LAN failure has been eliminated.

| Finding | Change |
|---|---|
| Control plane exposed on all interfaces without authentication | Default listener is `127.0.0.1`. Remote listening requires `NETCUT_API_TOKEN`; remote requests must authenticate. |
| Untrusted browser origins could still invoke API actions; Host-based rebinding risk | Requests reject untrusted origins before executing handlers. Token-free access requires a loopback connection and loopback Host, without forwarded-client headers. |
| nftables shell/rule injection and partial installation | Removed shell execution, validated IP/MAC/table values, and installed new rules in an nft transaction. |
| Release could match another target by IP prefix | Rule matching uses exact tokens; kernel handles must be numeric. Failed verification is reported. |
| Camera redirect bypass and active content served through the dashboard origin | Camera fetches reject redirects; image proxy rejects HTML and non-image content. |
| Windows DLL search could load a planted library | Load Npcap and dependencies only from Windows system/Npcap directories with restricted search flags. |
| Preview release could stop a real cut on the same IP | Windows and Linux adapters return immediately for dry-run release. |
| Release success reported before healing or despite injection failure | Join poison workers, repeat healing, and surface errors. Windows keeps failed-healing sessions for retries. |
| Dashboard count/filter disagreed with applied enforcement records | Active quarantine records drive device status, Restore buttons, counts and timers. Previews and shaping do not count as cuts. |
| Missing release-poll response interpreted as success | Failed polling now reports an error. API release errors return HTTP 500 with details. |
| Vault silently used a public default encryption key | Empty secret keys are rejected. This component currently has no production callers. |
| Non-DHCP UDP traffic accepted as DHCP | Require a valid source/destination port pair; parser tests are portable to Windows. |
| Timeouts and unreachable TCP destinations reported as successful latency probes | Only an actual connection refusal counts as a responding host; IPv6 targets use proper host/port formatting. |

## Local and remote access

**Localhost has no token requirement and no login prompt.** Start normally and
open `http://localhost:8080`. This trusts local users/processes on the PC.

For remote access, set a strong random `NETCUT_API_TOKEN`, start with
`-listen 0.0.0.0`, and use HTTPS through an appropriately configured proxy.
The browser accepts HTTP Basic authentication: any username, token as password.
CLI helpers read the token from the same environment variable and send a Bearer
header. Tokens are never accepted in URL query strings. Clients refuse redirects
to another origin. Keep the public Host and forwarded-client headers when proxying;
do not make remote requests appear to be direct localhost requests.

`ALLOWED_ORIGIN` can permit an exact trusted dashboard origin. CORS is not a
substitute for authentication. Direct public HTTP would expose credentials.

## Verification and limits

Run `go test ./pkg/... ./cmd/win-tool ./cmd/netcut-cli`, `npm.cmd --prefix web test`,
`npm.cmd --prefix web exec -- tsc --noEmit -p web/tsconfig.json`, and the dashboard
production build. Windows Go tests, frontend tests, TypeScript checking, and the
dashboard build pass. Linux and both macOS architectures can be cross-compiled
on Windows; native runtime and LAN tests still need execution on those systems.

The macOS version adds experimental native BPF ARP/NDP quarantine. It requires
explicit selection/opt-in, root, validated routes/current target MAC and both
forwarding settings off. BPF header preservation is configured and read back.
Restore uses saved mappings after the worker stops. Failed partial-apply cleanup
keeps a visible Restore/TTL owner. Dry runs never inject or stop live cuts;
live simulator fallback and native rate limiting are rejected.

Live Windows/Linux/macOS ARP/NDP behavior remains to be tested on a controlled LAN:
apply a short cut, verify IPv4 and IPv6 on the target, restore, then check TTL.
An applied record is not proof of isolation. A forced process termination cannot
guarantee healing. Router/switch defenses can prevent side-host enforcement;
use gateway enforcement where complete isolation is required.

Remaining scope includes a full dependency audit, reverse-proxy deployment
review, per-interface Windows forwarding/ICS validation, and broader testing of
all administrative endpoints. The vault still expects a high-entropy secret;
it is not a password-hardening/KDF service.
