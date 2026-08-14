# Focus Specification

Status: Validated
Date: 2026-08-15

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY define normative requirements.

## 1. Product objective

Focus MUST transform a general-purpose computer into a temporary work-only environment controlled by a selected profile, a concrete objective, and a minimum session duration.

Outside a Focus session, the computer MUST behave normally.

During a strict locked session, anything not explicitly allowed or confidently classified as relevant MUST be denied.

## 2. V1 platform scope

V1 MUST implement Linux system enforcement.

V1 MUST include:

- Rust policy core
- Privileged Rust daemon
- Local protected persistence
- Tauri 2 desktop app
- React, Vite, Tailwind CSS, and TypeScript UI
- Firefox extension
- Chromium extension
- Google Search filtering
- YouTube filtering
- Deterministic content rules
- Local ONNX classification fallback
- Application enforcement
- Network enforcement
- VPN abstraction
- WireGuard support
- OpenVPN support
- Generic VPN adapter framework
- Privileged-action broker
- Manual sessions
- One-time schedules
- Recurring schedules
- Reboot recovery
- Emergency unlock
- Local history
- Diagnostics
- CLI
- Linux packaging
- Automated tests and CI

V1 MUST NOT require a cloud account, cloud database, remote classifier, remote backend, or subscription.

## 3. Security invariants

### SEC-001

A session MUST NOT enter `LOCKED` until every protection required by its profile is healthy and verified.

### SEC-002

Closing or killing the desktop UI MUST NOT end a session.

### SEC-003

A reboot MUST NOT end a session whose minimum duration has not expired.

### SEC-004

Normal user applications MUST NOT directly edit protected Focus state.

### SEC-005

IPC clients request actions. `focusd` makes security decisions.

### SEC-006

Classifier failure, timeout, malformed output, or insufficient confidence MUST NOT result in an allow decision for ambiguous content.

### SEC-007

Loss of required browser protection MUST make that browser unavailable until protection is restored.

### SEC-008

User rules MUST NOT override immutable security invariants.

### SEC-009

Before `minimum_end_at`, a locked session MUST only end through a fully authorized emergency flow.

### SEC-010

Focus MUST NOT install a root certificate for HTTPS interception.

## 4. Session states

Required states:

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

Normal flow:

```text
IDLE
PREFLIGHT
ARMING
LOCKED
ENDING
IDLE
```

Emergency flow:

```text
LOCKED
EMERGENCY_PENDING
EMERGENCY_AUTHORIZED
ENDING
```

Recovery flow:

```text
boot
RECOVERING
LOCKED or PROTECTION_FAILURE
```

## 5. Session model

A session MUST store at least:

```text
id
objective
profile_id
profile_version
created_at
started_at
minimum_end_at
source
policy_snapshot
protection_requirements
emergency_policy
status
```

`source` MUST distinguish manual, one-time scheduled, and recurring scheduled sessions.

## 6. Objective and duration

A session MUST have a non-empty objective.

A minimum duration MUST be selected before arming.

The minimum duration MUST NOT be shortened while locked.

The objective MAY be provided as context to local classification, but MUST NOT be the sole security policy.

## 7. Profiles

V1 MUST provide at least:

```text
Mathematics
Physics
Programming
Science
Custom
```

A profile MUST be versioned.

An active session MUST use an immutable profile snapshot. Editing a profile later MUST NOT modify an active session.

Pre-session overrides MAY be applied before arming and MUST be frozen with the session snapshot.

## 8. Policy precedence

Policy evaluation MUST use this order:

```text
1 security invariant
2 active-session restriction
3 explicit block
4 explicit allow
5 local classification request
6 default deny
```

Unknown resources in strict mode MUST default to deny unless a specific approved rule applies.

## 9. Application policy

Applications MAY be allowed, blocked, or profile-specific.

Applications already running when a session starts MUST be evaluated during arming.

Blocked and unapproved applications MUST be closed. If Focus cannot remove a prohibited process required by the protection profile, arming MUST fail.

Application identity MUST NOT rely only on filename or window title.

Identity SHOULD use canonical path, filesystem identity, package metadata, executable fingerprint, parent context, and execution origin where available.

Renaming an explicitly blocked binary MUST NOT be sufficient to bypass its block.

## 10. Programming workspaces

Programming profiles MUST support legitimate build and development workflows.

They MAY allow approved toolchains and workspace roots.

New binaries built inside approved development roots MAY run without manual registration.

An explicitly blocked executable copied into an approved workspace MUST remain blocked.

## 11. Browser support

V1 MUST support Firefox and at least one Chromium-based browser path through a shared WebExtension codebase.

A browser requiring filtering MUST only be usable when:

- The browser is supported.
- The Focus extension is installed.
- The Focus extension is enabled.
- The native messaging bridge is available.
- Extension heartbeat is healthy.
- Required managed browser policy is active.

Private or incognito browsing MUST be disabled when Focus cannot guarantee equivalent enforcement there.

## 12. Browser heartbeat

The browser extension MUST report browser instance, extension version, and policy version to `focusd` through the native bridge.

If heartbeat expires during a strict session, the browser MUST be considered unprotected and MUST be blocked or terminated.

## 13. Web policy

Domains MUST support the states:

```text
Allowed
Blocked
Filtered
```

Google and YouTube are filtered surfaces in V1.

Defaults are data, not hard-coded policy invariants.

## 14. Google Search

Focus MUST extract a Google search query and evaluate it using deterministic rules first.

If deterministic rules are inconclusive, Focus MUST request local classification.

A blocked query MUST prevent normal use of the search-results page.

A locked session MUST NOT show an instant override action such as Continue Anyway.

## 15. YouTube

Strict mode MUST block YouTube Shorts URLs and Shorts surfaces.

Recommendation-heavy and trending-oriented surfaces SHOULD be neutralized.

Relevant educational and technical videos MAY be allowed.

Distracting videos MUST be blocked.

If sufficient classification context cannot be obtained, the result MUST fail closed.

## 16. Local classification

The classification pipeline MUST use deterministic rules before ML inference.

ML inference MUST run locally and outside the privileged daemon process.

A classification result MUST include category, relevance, confidence, and model version.

Low-confidence results MUST be blocked.

The cache key MUST include content fingerprint, policy or profile version, and model version.

## 17. Network enforcement

Focus MUST enforce network policy independently of the browser extension.

Linux enforcement MUST use Focus-owned firewall objects and MUST NOT flush the global nftables ruleset.

Focus SHOULD support per-process or per-cgroup network classes for browser, development, VPN, Focus system processes, and blocked processes.

## 18. DNS and tunnel policy

During strict sessions, unauthorized DNS changes and direct unapproved resolver paths MUST be restricted.

Unapproved HTTP proxies, HTTPS proxies, SOCKS proxies, SSH dynamic proxies, Tor paths, and equivalent tunnels MUST be denied where technically enforceable.

Suspicious network mutations MUST be blocked, reverted, or cause `PROTECTION_FAILURE`.

## 19. VPN model

Focus MUST remain provider-neutral.

Required adapter categories:

```text
WireGuard
OpenVPN
NetworkManager
Native application framework
Browser extension framework
```

A VPN identity SHOULD include adapter type, configuration fingerprint, executable identity, expected interfaces, expected endpoints when meaningful, and allowed capabilities.

Approved VPNs MAY connect, disconnect, and reconnect during a session when policy allows.

An approved VPN MUST NOT bypass Focus web, process, network, or browser policy.

Unknown VPN mechanisms MUST NOT be approved while a session is locked.

## 20. Privileged actions

Focus MUST use typed privileged actions instead of arbitrary root command execution.

Allowed action categories MAY include approved VPN connect and disconnect operations and explicitly approved development operations.

The privileged broker MUST NOT expose arbitrary shell execution.

A strict session MUST deny privilege operations capable of stopping Focus, replacing its firewall state, deleting protected state, or otherwise trivially disabling enforcement.

## 21. Sudo security gate

Linux V1 MUST NOT claim full locked protection if an unrestricted root path remains available to the normal user during the session.

Privilege-enforcement implementation MUST be validated in a disposable VM before host installation.

If this gate cannot be satisfied, development MUST stop and the privilege architecture MUST return to review.

## 22. Storage

Critical state MUST be root-owned and conceptually stored under `/var/lib/focus/`.

Critical state includes active session, profiles, schedules, VPN identities, emergency state, security journal, and schema migrations.

UI-only preferences MAY remain in the normal user configuration directory.

The UI MUST NOT issue arbitrary SQL.

## 23. Transactional persistence

Critical state transitions MUST be crash-safe.

Partial or unreadable state MUST NOT silently terminate a locked session.

Recovery SHOULD prefer a restrictive state until consistency is established.

## 24. Reboot recovery

At boot, `focusd` MUST inspect protected state before requiring the desktop UI.

If a session is still active, the daemon MUST enter `RECOVERING`, restore required protections, verify health, and return to `LOCKED`.

If restoration fails, Focus MUST enter `PROTECTION_FAILURE`.

## 25. Time integrity

A monotonic clock SHOULD measure duration within one boot.

Persistent UTC timestamps MUST support reboot recovery.

A significant manual system-clock mutation MUST NOT silently shorten a locked session.

## 26. Scheduler

The daemon MUST support manual, one-time, and recurring sessions.

If a scheduled session becomes due while another session is active, V1 MUST keep the active session authoritative and mark the new one as missed because of the active session.

V1 MUST NOT automatically merge overlapping sessions.

## 27. Emergency exit

V1 emergency exit MUST require all three conditions:

1. Mandatory reason
2. Fixed 10-minute delay
3. Valid recovery code

The recovery code MUST be stored only in a non-reversible verification form.

Reboot MUST NOT reset or bypass the emergency delay.

## 28. Health model

Each protection subsystem MUST report one of:

```text
Healthy
Degraded
Failed
NotRequired
```

The desktop UI MAY show `Locked` only when all critical required protections are healthy.

If a critical protection fails during a session, Focus MUST reduce functionality rather than reduce enforcement where possible.

## 29. Privacy

V1 MUST be local-first.

Focus MUST NOT require an account, cloud service, remote classifier, or personal telemetry.

Full URLs and search history MUST NOT be retained by default.

Security logs SHOULD retain only information necessary for diagnostics and enforcement audit.

## 30. Desktop UX

Primary navigation MUST contain:

```text
Focus
Profiles
Rules
Schedule
History
Settings
```

The normal start screen SHOULD require only objective, profile, duration, and confirmation for an already configured user.

The locked screen MUST emphasize remaining time, objective, profile, lock state, and protection health.

Emergency exit MUST NOT be the dominant locked-screen action.

## 31. Accessibility

V1 SHOULD support full keyboard navigation, visible focus states, semantic controls, sufficient contrast, screen-reader labels, and reduced-motion preferences.

## 32. IPC

All daemon IPC MUST use a typed, versioned protocol.

The daemon MUST validate socket permissions, peer identity where available, client type, protocol version, and requested operation.

Knowing the socket path MUST NOT grant security authority.

## 33. Platform boundary

`focus-core` MUST remain independent of Linux APIs, browser APIs, Tauri, nftables, systemd, ONNX runtime implementation, and VPN vendors.

V1 implements a Linux backend. Windows and macOS remain future backends behind the same platform contract.

## 34. Packaging

The `.deb` package is the primary complete Linux installer.

It MUST install the required system service, CLI, desktop application, browser bridge, managed browser integration, classifier assets, and system integration.

An AppImage MAY be distributed, but MUST clearly require or bootstrap the persistent system components needed for full protection.

## 35. Testing

The project MUST include:

- Unit tests
- State-machine tests
- Property tests for critical invariants
- Linux integration tests
- Browser end-to-end tests
- VPN tests
- Reboot recovery tests
- Privilege tests
- Bypass regression tests

Every security bypass discovered after implementation MUST become a regression test.

## 36. Required bypass scenarios

The regression suite MUST cover at least:

```text
kill desktop
kill extension
kill browser bridge
kill classifier
restart daemon
reboot
rename blocked app
new compiled executable
change DNS
DoH
unknown WireGuard
unknown OpenVPN
approved VPN
HTTP proxy
SOCKS proxy
SSH dynamic proxy
Tor
system clock change
sudo shell
systemctl stop focusd
firewall mutation
protected-state deletion
private browsing
scheduled-session collision
```

## 37. Repository text policy

The repository MUST NOT contain Unicode character U+2014 in tracked text files.

CI MUST scan tracked text files and fail when that code point is found.

Documentation, comments, examples, code strings, and configuration are all covered by this rule.

## 38. Definition of Done

Focus V1 is functionally complete when a user can start a two-hour Programming session, use an approved VPN, edit and compile code, use approved documentation, perform relevant Google searches, watch relevant technical YouTube content, and remain blocked from distracting applications, websites, Shorts, unknown VPNs, proxy bypasses, privilege bypasses, extension removal bypasses, UI-kill bypasses, and reboot bypasses.

At the normal end time, Focus MUST safely restore the system changes it owns, record the session, and return to normal mode.
