# Focus Architecture

Status: Validated
Date: 2026-08-15

## Architecture rule

The desktop interface has no security authority.

The privileged daemon remains the source of truth for session state, policy decisions, persistence, enforcement, recovery, and scheduling. Closing the desktop app must not stop a Focus session.

## Top-level components

```text
focus-desktop
      |
      | typed local IPC
      v
    focusd <----- focusctl
      ^
      |
focus-browser-bridge
      ^
      |
Firefox / Chromium extension
```

Supporting crates:

```text
focus-core
focus-protocol
focus-storage
focus-classifier
focus-platform
focus-testkit
```

Linux-specific enforcement lives outside the policy core.

## Monorepo

Target structure:

```text
Focus/
├── crates/
│   ├── focus-core/
│   ├── focus-protocol/
│   ├── focus-storage/
│   ├── focus-classifier/
│   ├── focus-platform/
│   └── focus-testkit/
├── bins/
│   ├── focusd/
│   ├── focusctl/
│   └── focus-browser-bridge/
├── apps/
│   ├── desktop/
│   └── browser/
├── platform/
│   ├── linux/
│   ├── windows/
│   └── macos/
├── models/
├── packaging/
├── docs/
└── .github/
```

## focus-core

`focus-core` is platform-independent and owns domain semantics.

It understands concepts such as:

```text
Session
Profile
Policy
Decision
Schedule
EmergencyUnlock
VpnIdentity
ProtectionRequirement
```

It does not depend on Linux APIs, Tauri, browser APIs, nftables, systemd, ONNX runtime details, or VPN vendors.

## Decision ordering

Policy evaluation follows this precedence:

```text
1 security invariant
2 active-session restriction
3 explicit block
4 explicit allow
5 classification request
6 default deny
```

A user allow rule can never override a security invariant.

## Session state machine

Normative states:

```text
IDLE
PREFLIGHT
ARMING
LOCKED
EMERGENCY_PENDING
EMERGENCY_AUTHORIZED
ENDING
RECOVERING
PROTECTION_FAILURE
```

The important invariant is that a locked session cannot reach idle before the minimum end time unless the emergency flow has been fully authorized.

## Transactional activation

Session activation is transactional:

```text
validate request
run preflight
persist ARMING
freeze policy snapshot
close forbidden apps
arm browser guard
arm process guard
arm network guard
arm VPN guard
arm privilege guard
verify health
persist LOCKED
```

If any critical protection fails, Focus never reports the session as locked.

## focusd

`focusd` is a root-owned Linux service started by systemd.

Responsibilities:

- Session orchestration
- Policy enforcement coordination
- Protected persistence
- Scheduling
- Recovery
- Local IPC authorization
- Platform backend ownership

It must keep its privileged code surface small.

## IPC

Linux IPC uses a root-owned Unix domain socket, conceptually:

```text
/run/focus/focusd.sock
```

Messages are typed and versioned through `focus-protocol`.

Each request contains at least:

```text
protocol_version
request_id
client_kind
payload
```

Client types:

```text
Desktop
Cli
BrowserBridge
Classifier
```

Capabilities are enforced by the daemon. A browser bridge cannot edit profiles or start sessions merely because it can reach the socket.

## Desktop

Stack:

```text
Tauri 2
React
TypeScript
Vite
Tailwind CSS
```

The Tauri process is not root. React never calls system utilities directly.

Desktop actions are requests to `focusd`.

## Browser architecture

Firefox and Chromium share a TypeScript WebExtension core.

Flow:

```text
content script
    |
background / service worker
    |
native messaging
    |
focus-browser-bridge
    |
focusd
```

The bridge translates protocols but does not own policy logic.

## Browser protection health

A browser is considered protected only when all required conditions hold:

- Supported browser
- Focus extension installed
- Focus extension enabled
- Native bridge available
- Heartbeat healthy
- Required managed policies active

If the extension heartbeat disappears during a strict session, the browser is blocked or terminated until protection returns.

## Browser managed policy

Strict mode configures browser policy so that the Focus extension cannot simply be disabled or removed through the normal browser UI. Private or incognito browsing is disabled where extension enforcement cannot be guaranteed.

## Google and YouTube

Google and YouTube are semantic-filtering surfaces.

Google flow:

```text
extract query
apply deterministic rules
use local classifier if ambiguous
allow or block
```

YouTube additionally neutralizes distracting surfaces such as Shorts and recommendation-heavy feeds.

## Classification process boundary

ML inference does not run inside the root daemon.

```text
focusd
  |
  | sanitized request
  v
unprivileged classifier process
  |
  v
classification result
```

The policy engine remains the final authority.

Classifier crash, timeout, malformed response, or low confidence causes an ambiguous request to be blocked.

## Linux process enforcement

The Linux backend combines:

- Pre-execution control where feasible
- Runtime process monitoring
- Executable identity based on more than filename
- Trusted development-workspace execution rules

The planned pre-execution mechanism uses fanotify permission events where supported.

## Development workspaces

Programming profiles may trust specific workspace roots. Newly compiled binaries inside those roots may execute without manual registration.

Explicitly blocked software remains blocked even if copied into a trusted development directory.

## Linux network enforcement

Network protection has three layers:

```text
host firewall
per-process or per-cgroup policy
browser semantic filtering
```

Focus owns its own nftables objects and never flushes the global ruleset.

The architecture reserves cgroup v2 and small eBPF programs for process-aware network control.

Business policy must remain in userspace. eBPF receives prepared allow or deny state rather than domain logic.

## DNS

Focus maintains policy-aware domain resolution state with expiration. Unauthorized DNS changes and direct external resolver paths are restricted during strict sessions.

Focus does not install a local TLS interception certificate.

## VPN architecture

VPN support is provider-neutral.

```text
VpnManager
├── WireGuardAdapter
├── OpenVpnAdapter
├── NetworkManagerAdapter
├── NativeVpnAdapter
└── BrowserVpnAdapter
```

A `VpnIdentity` records enough information to distinguish an approved mechanism from an unknown tunnel.

Approved VPNs may transport traffic but never own access policy.

## Privileged operations

Focus exposes a small typed privileged-action broker instead of arbitrary root command execution.

Examples of valid action categories:

```text
VpnConnect
VpnDisconnect
DockerStart
DockerStop
```

Arbitrary shell execution is not part of the broker interface.

During a strict session, privilege escalation paths capable of disabling Focus must be denied if the platform claims full protection.

## Storage

Critical state is root-owned, conceptually under:

```text
/var/lib/focus/
```

Critical data includes:

- Active session
- Profiles and versions
- Schedules
- VPN identities
- Emergency state
- Security journal
- Migration metadata

Pure UI preferences may remain under the normal user configuration directory.

## Reboot and recovery

At boot, `focusd` loads protected state before the desktop application is required.

If a locked session is still active:

```text
boot
focusd
RECOVERING
reapply protections
verify health
LOCKED
```

If protection cannot be restored, Focus enters `PROTECTION_FAILURE` rather than silently ending the session.

## Time model

Within a boot, session duration uses a monotonic clock where possible. UTC state is persisted for reboot recovery.

A suspicious system clock change never silently shortens a session.

## Platform abstraction

Conceptual interface:

```text
preflight()
snapshot()
arm_process_guard()
arm_network_guard()
arm_browser_guard()
arm_privilege_guard()
inspect_vpns()
health()
restore()
```

V1 implements `LinuxBackend`. Future `WindowsBackend` and `MacOSBackend` reuse the same domain core.

## Trust boundaries

Untrusted:

- Web pages
- Internet content
- User applications
- VPN servers
- React UI input

Limited trust:

- Tauri shell
- Browser extension
- Native messaging bridge
- Classifier process

Trusted:

- `focus-core` policy semantics
- `focusd`
- Root-owned state
- Linux enforcement backend
- Kernel enforcement objects created by Focus

## Packaging

The `.deb` package is the primary complete Linux installation because Focus requires persistent system integration.

An AppImage may provide the desktop UI, but it must either connect to an already installed system service or clearly bootstrap the required privileged components.

## Testing strategy

Testing is split into:

1. Pure domain tests
2. State-machine and property tests
3. Linux integration tests in disposable VMs
4. Browser end-to-end tests
5. Security bypass regression tests

Every discovered bypass becomes a permanent regression scenario.
