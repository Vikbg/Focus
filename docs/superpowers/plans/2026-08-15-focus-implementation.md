# Focus Implementation Plan

> For agentic workers: use Superpowers task execution with isolated branches or worktrees, TDD, explicit review gates, and frequent commits.

Status: Validated
Date: 2026-08-15

## Goal

Build Focus V1 as a Linux-first, local-only, system-level focus environment with a platform-independent policy core, a privileged daemon, browser filtering, network and VPN enforcement, local classification, a polished Tauri desktop app, and strict security regression testing.

## Architecture summary

- `focus-core` owns platform-independent semantics.
- `focusd` is the privileged security authority.
- `focus-protocol` defines typed local IPC.
- `focus-storage` owns transactional protected state.
- `focus-classifier` provides deterministic rules and local ONNX fallback.
- `focus-platform` defines enforcement interfaces.
- `platform/linux` implements Linux enforcement.
- `focus-browser-bridge` connects WebExtensions to the daemon.
- `focusctl` is a non-authoritative CLI client.
- The desktop app uses Tauri 2, React, Vite, Tailwind CSS, and TypeScript.

## Global constraints

- Linux is the only system backend implemented in V1.
- Windows and macOS must remain possible through backend isolation.
- No cloud service is required.
- No root TLS certificate or HTTPS interception.
- Fail closed for ambiguous or critical protection failures.
- The desktop UI never owns security state.
- Locked sessions survive reboot.
- Firefox and Chromium are supported.
- Google and YouTube are filtered surfaces.
- YouTube Shorts is blocked in strict mode.
- Classification is deterministic first and local ONNX second.
- VPN architecture is provider-neutral.
- WireGuard and OpenVPN are first-class V1 adapters.
- Privileged operations use typed broker actions.
- The `.deb` package is the primary complete Linux installation.
- Every bypass becomes a regression test.
- Tracked text files must not contain Unicode U+2014.

## Delivery phases

```text
P0 Foundation
P1 Session engine and daemon
P2 Linux process and privilege enforcement
P3 Network and VPN enforcement
P4 Local classification
P5 Browser enforcement
P6 Desktop product
P7 Packaging and hardening
```

Each phase ends with:

```text
targeted tests
subsystem tests
self-review
security review when applicable
commit or PR checkpoint
```

# P0 Foundation

## Task 1: Repository bootstrap

Create the public repository, add the validated design, architecture, specification, and implementation plan, add the license, root manifests, ignore rules, and repository text policy.

Validation:

```bash
python3 scripts/check-no-em-dash.py
```

Expected: exit 0.

Commit intent:

```text
chore: initialize Focus repository
```

## Task 2: Workspace scaffolding

Create these Rust packages:

```text
crates/focus-core
crates/focus-protocol
crates/focus-storage
crates/focus-classifier
crates/focus-platform
crates/focus-testkit
bins/focusd
bins/focusctl
bins/focus-browser-bridge
platform/linux
```

Create JS workspaces:

```text
apps/desktop
apps/browser
```

Validation:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
pnpm -r typecheck
```

## Task 3: Core decision types

Create focused files for:

```text
decision.rs
policy.rs
profile.rs
session.rs
state_machine.rs
schedule.rs
emergency.rs
vpn.rs
```

Start with a failing test for unresolved policy:

```rust
#[test]
fn ambiguous_policy_requests_classification() {
    let decision = PolicyEngine::default().decide(&ambiguous_context());
    assert_eq!(decision, Decision::Classify);
}
```

Then implement only enough to make the test pass.

## Task 4: Policy precedence

Test the exact order:

```text
security invariant
session restriction
explicit block
explicit allow
classification
default deny
```

Required negative test:

```rust
#[test]
fn explicit_allow_cannot_override_security_invariant() {
    let policy = policy_allowing("focusd-stop");
    let decision = policy.decide(&security_sensitive_action("focusd-stop"));
    assert!(matches!(decision, Decision::Block(_)));
}
```

## Task 5: Session state machine

Write the early-end rejection test first:

```rust
#[test]
fn locked_session_cannot_end_early_without_emergency_authorization() {
    let mut session = locked_session_with_remaining_time();
    let result = session.transition(SessionState::Ending);
    assert_eq!(result, Err(TransitionError::MinimumDurationNotReached));
}
```

Add property tests proving no illegal route from `LOCKED` to `IDLE` exists before the minimum end time without emergency authorization.

## Task 6: Profile versioning

Implement immutable session snapshots. A running session created from profile version 5 must remain on version 5 after the user creates profile version 6.

# P1 Session engine and daemon

## Task 7: Versioned IPC protocol

Create typed envelopes with:

```text
protocol_version
request_id
client_kind
request
response
```

Client kinds:

```text
Desktop
Cli
BrowserBridge
Classifier
```

Test capability separation. `BrowserBridge` must not be able to start sessions or edit profiles.

## Task 8: Transactional storage

Use SQLite behind a domain-specific interface.

Production path conceptually:

```text
/var/lib/focus/focus.db
```

Test with temporary databases.

Required interface shape:

```rust
trait FocusStore {
    fn active_session(&self) -> Result<Option<Session>>;
    fn persist_transition(&self, transition: &Transition) -> Result<()>;
    fn append_security_event(&self, event: &SecurityEvent) -> Result<()>;
}
```

Test interrupted writes and migration failure behavior.

## Task 9: Minimal daemon

Create Unix-socket IPC with a test socket path.

First externally visible behavior:

```bash
focusctl status
```

Expected conceptually:

```text
Focus daemon: running
State: Idle
```

## Task 10: Platform abstraction

Create an async platform backend contract and a fake backend for daemon tests.

The fake backend must support deliberate failures for process, network, browser, and privilege guards.

## Task 11: Transactional arming

Write a failing test proving that network-guard failure prevents `LOCKED`.

Activation sequence:

```text
preflight
persist ARMING
freeze policy
close blocked apps
arm guards
verify health
persist LOCKED
```

## Task 12: Crash recovery

Simulate a crash after persisting `ARMING`. On restart, the daemon must enter `RECOVERING` and either restore `LOCKED` or enter `PROTECTION_FAILURE`.

## Task 13: Scheduler

Support manual, one-time, and recurring sessions.

Collision rule:

```text
active session exists
new scheduled session becomes due
keep active session
mark new schedule occurrence missed_due_to_active_session
```

## Task 14: Emergency flow

Implement mandatory reason, 10-minute delay, and recovery-code verification.

Tests must prove:

```text
correct code at 9m59s -> denied
correct code at 10m00s -> allowed
reboot during delay -> delay remains effective
```

## Task 15: CLI

Implement:

```text
focusctl status
focusctl session
focusctl doctor
focusctl vpn list
focusctl vpn up <id>
focusctl vpn down <id>
```

The CLI remains only a daemon client and must not become a bypass.

# P2 Linux process and privilege enforcement

All privileged enforcement work starts in disposable Linux VMs.

## Task 16: Linux preflight

Detect systemd, nftables, cgroup v2, fanotify support, browser installation, native-messaging locations, filesystem permissions, and required kernel capabilities.

A missing critical requirement must prevent `LOCKED`.

## Task 17: Executable identity

Create a structured executable identity using canonical path, device, inode, optional digest, package metadata when available, and parent context.

Renaming a blocked binary must not automatically permit it.

## Task 18: Close prohibited applications

Use graceful termination first, then force termination when required.

If a prohibited process required by policy cannot be removed, arming must fail.

## Task 19: Pre-execution guard

Prototype fanotify permission control in a VM with dedicated fixture binaries.

Required tests:

```text
blocked fixture -> denied before execution
allowed fixture -> executes
```

Add a runtime watchdog as a second layer.

## Task 20: Development execution roots

Compile a real fixture with GCC or Clang inside an approved workspace and prove it can run.

Copy an explicitly blocked fixture into the same workspace and prove it remains blocked.

## Task 21: Privilege restriction security gate

This task is pass or fail.

During a locked test session, attempts such as these must fail:

```bash
sudo -s
sudo bash
sudo sh
sudo systemctl stop focusd
sudo nft flush ruleset
sudo python3 -c 'print("root bypass fixture")'
```

At least one explicitly approved typed broker action must succeed.

If unrestricted root remains available, stop and return the privilege architecture to review.

## Task 22: Typed privileged broker

Expose only typed actions such as:

```text
VpnConnect
VpnDisconnect
DockerStart
DockerStop
```

Do not expose arbitrary command, arbitrary shell, or arbitrary filesystem-write APIs.

## Task 23: systemd service

Install `focusd` as a root-owned service that starts at boot and restarts on unexpected failure.

Reboot test:

```text
locked session
reboot
focusd starts automatically
RECOVERING
LOCKED
```

# P3 Network and VPN enforcement

## Task 24: Focus-owned nftables objects

Create and remove only Focus-owned nftables state.

Regression test: unrelated existing rules remain unchanged after Focus starts and stops.

## Task 25: Strict outbound baseline

Test traffic from multiple contexts using tools such as curl, wget, and netcat fixtures.

Unknown paths must fail closed during strict sessions.

## Task 26: cgroup process classes

Create classes for:

```text
browser
development
vpn
system
blocked
```

Test that Firefox and compiler children enter the correct classes.

## Task 27: cgroup eBPF enforcement

Keep eBPF programs small and policy-free. They consume maps generated by the daemon.

Isolated VM tests must prove allowed and denied egress for fixture cgroups.

## Task 28: DNS policy

Maintain domain-to-address entries with expiry and policy version.

Tests must prove TTL expiration removes stale allow state.

## Task 29: Proxy and tunnel bypass suite

Test:

```text
HTTP proxy
SOCKS proxy
SSH dynamic proxy
alternate DNS
Tor-like local fixture
```

Each path must be explicitly approved or blocked.

## Task 30: WireGuard adapter

Implement the generic `VpnAdapter` contract for approved WireGuard profiles.

Tests:

```text
approved profile -> connect succeeds
unknown profile -> denied
```

Provider names must not appear in policy-core logic.

## Task 31: OpenVPN adapter

Apply the same identity and policy model to OpenVPN fixtures.

## Task 32: Generic VPN adapter framework

Add NetworkManager, native-app, and browser-extension adapter interfaces without hard-coding provider behavior into `focus-core`.

## Task 33: VPN bypass regression

Core scenario:

```text
blocked destination
connect approved VPN
retry blocked destination
still blocked
```

Also test reconnect, server change when permitted, unknown tunnel, and routing-table mutation.

# P4 Local classification

## Task 34: Request normalization

Normalize Unicode, case, whitespace, known tracking parameters, and content kind before policy evaluation.

## Task 35: Deterministic rules

Support categories such as Mathematics, Physics, Science, Programming, Entertainment, Social, and Unknown.

Rules must decide obvious domains and surfaces without invoking ML.

## Task 36: Unprivileged classifier process

Run local inference outside the root daemon. Kill the classifier during tests and prove the daemon survives.

## Task 37: ONNX inference

Invoke ONNX only after deterministic rules remain inconclusive.

Build fixture cases for relevant and distracting content.

## Task 38: Confidence and fail-closed logic

Tests:

```text
low confidence -> block
timeout -> block
malformed response -> block
```

## Task 39: Classification cache

Key cache entries by content fingerprint, profile or policy version, and model version.

Changing either version must invalidate the cache.

# P5 Browser enforcement

## Task 40: Shared WebExtension workspace

Create a shared TypeScript base with browser-specific manifests for Firefox and Chromium.

Required build commands:

```bash
pnpm browser:build:firefox
pnpm browser:build:chromium
```

## Task 41: Native messaging

Keep `focus-browser-bridge` limited to protocol translation, browser-instance identity, and heartbeat forwarding.

## Task 42: Browser heartbeat

When heartbeat expires, the daemon marks the browser unprotected and the Linux backend blocks or terminates it.

## Task 43: Managed browser policy

Use disposable browser profiles to verify that strict sessions require the Focus extension and remove unprotected private or incognito paths.

## Task 44: Google Search filtering

End-to-end cases:

```text
quadratic formula -> allow under Mathematics
Maxwell equations -> allow under Physics
Rust ownership -> allow under Programming
celebrity gossip -> block
```

## Task 45: YouTube surface neutralization

Block Shorts and remove distracting recommendation or trending surfaces during strict sessions.

## Task 46: YouTube video classification

Use video ID, title, channel, search context, and available metadata.

Test relevant educational content, distracting content, and ambiguous content.

## Task 47: Browser VPN coexistence

Use a proxy-extension fixture to prove that browser VPN transport does not disable Focus filtering.

## Task 48: Full browser end-to-end gate

Both Firefox and Chromium must pass:

```text
Google allow
Google block
YouTube allow
YouTube block
Shorts block
heartbeat failure
private-mode denial
proxy-extension coexistence
daemon unavailable fail-closed behavior
```

# P6 Desktop product

## Task 49: Tauri shell

The Tauri process must not run privileged commands directly. All state-changing actions go through typed daemon IPC.

## Task 50: Design tokens

Create central tokens for spacing, typography, radii, borders, motion durations, and semantic states.

Use a 4 px spacing grid.

## Task 51: Application shell

Primary navigation:

```text
Focus
Profiles
Rules
Schedule
History
Settings
```

Test keyboard navigation and route state.

## Task 52: Session launcher

Build objective, profile, duration, preflight summary, recovery-code presentation, and start confirmation.

Never show `Locked` if preflight or arming fails.

## Task 53: Locked view

Show remaining time, objective, profile, lock state, and protection health with minimal visual noise.

## Task 54: Profile management

Support built-in and custom profiles, development roots, apps, web rules, VPN rules, and protection requirements.

## Task 55: Rules UI

Sections:

```text
Applications
Web
Content
Network
VPN
System
```

Low-level Linux details remain under advanced diagnostics.

## Task 56: Scheduling UI

Create manual, one-time, and recurring schedules and show missed occurrences clearly.

## Task 57: History

Show date, profile, objective, duration, completion reason, missed schedule state, and emergency use without aggressive gamification.

## Task 58: Settings and diagnostics

Surface health for daemon, process guard, network guard, browser guard, classifier, VPN adapters, and privilege guard.

## Task 59: Onboarding

Flow:

```text
Welcome
System protection
Browser protection
First profile
Diagnostics
Ready
```

Every privileged permission request must explain its purpose.

## Task 60: Command palette and accessibility

Support keyboard-first operation, visible focus, reduced motion, semantic labels, and automated accessibility checks.

# P7 Packaging and hardening

## Task 61: Debian package

The package must install:

```text
desktop app
focusd
focusctl
browser bridge
systemd service
native-messaging manifests
managed-browser policy
classifier assets
ONNX model
```

Validate on a clean disposable VM.

## Task 62: AppImage

If `focusd` is already installed, connect normally. Otherwise explain that full protection requires system-component installation or an explicit privileged bootstrap.

## Task 63: CI

Separate workflows for Rust, frontend, browser, security, and packaging.

Minimum PR checks:

```text
cargo fmt
cargo clippy with warnings denied
cargo test
TypeScript lint
typecheck
frontend tests
Firefox extension build
Chromium extension build
repository text policy
```

## Task 64: Secret protection

Add secret scanning and fixture-only VPN configurations. Real VPN keys and recovery codes must never enter the repository.

## Task 65: Threat model

Document assets, trust boundaries, attacker capabilities, in-scope bypasses, out-of-scope physical attacks, privilege assumptions, VPN assumptions, browser assumptions, and fail-closed behavior.

## Task 66: Full bypass suite

Release-blocking cases include:

```text
kill UI
kill extension
kill bridge
kill classifier
restart daemon
reboot
rename blocked app
new compiled binary
DNS change
DoH
unknown WireGuard
unknown OpenVPN
approved VPN
HTTP proxy
SOCKS
SSH dynamic proxy
Tor
clock change
sudo shell
systemctl stop daemon
nftables mutation
protected-state deletion
private browsing
schedule collision
```

## Task 67: Resource usage

Measure daemon CPU and memory, classifier memory, extension background activity, and behavior with the desktop window closed.

Continuous ML inference while idle is unacceptable.

## Task 68: Clean VM release scenario

Complete this full release test:

```text
install
onboard
create Programming profile
approve VPN fixture
start two-hour session
compile code
browse documentation
filter Google
filter YouTube
attempt bypasses
reboot
recover session
finish session
uninstall cleanly
```

# Branch strategy

Use focused branches:

```text
agent/foundation
agent/session-engine
agent/linux-enforcement
agent/network-vpn
agent/classifier
agent/browser
agent/desktop
agent/packaging-hardening
```

Do not implement large features directly on `main`.

# Per-task workflow

Each implementation task follows:

```text
1 write the failing test
2 run it and confirm expected failure
3 write the smallest implementation
4 run the targeted test
5 run subsystem tests
6 run repository text policy
7 self-review correctness
8 self-review security impact
9 commit narrowly
```

# Security gates

The following components are tested in disposable Linux VMs before host installation:

```text
fanotify execution denial
privilege restriction
nftables enforcement
cgroup and eBPF enforcement
```

The privilege task is a hard gate. If arbitrary root access remains available during a session that claims full protection, stop implementation and revise architecture rather than shipping a partial security claim.

The browser task is also fail closed. Extension loss, bridge loss, or daemon loss must not produce unrestricted browsing during a strict session.

# Release sequence

Suggested pre-release milestones:

```text
v0.1.0 core, protocol, storage, daemon, fake backend
v0.2.0 Linux process enforcement
v0.3.0 network and VPN enforcement
v0.4.0 browser and classifier
v0.5.0 complete desktop product
v0.9.0 packaging and bypass hardening
v1.0.0 all acceptance gates passing
```

# Final verification

Before V1 release:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
pnpm -r lint
pnpm -r typecheck
pnpm -r test
python3 scripts/check-no-em-dash.py
```

Then run Linux integration, Firefox, Chromium, VPN, reboot, privilege, bypass, and clean-package suites.

A release is blocked by any unexpected bypass or any critical protection that cannot prove healthy state.
