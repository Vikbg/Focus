# Focus Product Design

Status: Validated
Date: 2026-08-15

## Vision

Focus temporarily turns a general-purpose computer into a work-only environment. Outside a Focus session, the machine behaves normally. During a locked Focus session, only resources relevant to the selected work profile and objective remain available.

Focus is not a Pomodoro timer and not only a website blocker. It is designed to feel like a system capability that enforces a temporary work environment.

Core product promise:

> Turn your computer into a workspace. Nothing else.

## Product principles

1. Strict without obstructing legitimate work.
2. Local-first privacy.
3. Default deny during locked sessions.
4. Minimal daily interaction.
5. No distracting gamification.
6. Clear and truthful protection state.
7. Strong recovery semantics after crash or reboot.
8. Cross-platform product model with Linux-first enforcement.

## Primary flow

A normal session starts with four inputs:

- Objective
- Profile
- Minimum duration
- Start Focus

Before activation, Focus presents the full session summary and any exceptions. Once the user starts the session, its policy snapshot becomes immutable until the minimum duration expires or the emergency flow succeeds.

## Main navigation

The desktop application contains six primary areas:

- Focus
- Profiles
- Rules
- Schedule
- History
- Settings

The Focus screen stays intentionally sparse. Configuration-heavy surfaces live in their dedicated areas.

## Focus profiles

Built-in profiles:

- Mathematics
- Physics
- Programming
- Science
- Custom

A profile defines application policy, web policy, content classification context, network policy, VPN permissions, privileged actions, and required protections.

Users may duplicate profiles to create specialized environments such as Programming / Rust or Physics / Olympiad.

## Locked session experience

The locked screen shows only essential information:

- Remaining time
- Objective
- Profile
- Locked status
- Protection health summary

Focus does not use streak pressure, confetti, motivational popups, or other engagement mechanics that could become distractions.

## Application policy

Applications can be allowed, blocked, or profile-specific. Unknown applications are denied during strict sessions unless a development workspace rule explicitly permits newly compiled software.

Blocked applications already running when a session starts are closed automatically.

## Web policy

Domains have three states:

- Allowed
- Blocked
- Filtered

Examples of filtered services are Google and YouTube, where the domain itself is useful but specific searches or content can be distracting.

## Google filtering

Google search queries are evaluated using deterministic rules first. Ambiguous queries are sent to a small local classifier. A low-confidence result is blocked.

A blocked page explains that the search does not match the current session. There is no instant bypass button during a locked session.

## YouTube filtering

YouTube becomes a resource search surface rather than an entertainment feed.

During strict mode:

- Shorts are blocked.
- Recommendation-heavy surfaces are neutralized.
- Relevant technical or educational videos may be allowed.
- Distracting content is blocked.

## Browser extension

Firefox and Chromium are supported in V1 through a shared WebExtension codebase with small browser-specific adaptations.

The extension stays intentionally small. Complex configuration remains in the desktop application.

## Local classification

The classification pipeline is hybrid:

1. Deterministic rules handle obvious cases.
2. A small embedded ONNX model handles ambiguous content.
3. Low confidence or classifier failure results in a block.

Ollama is not required. A future optional integration may exist, but Focus V1 must remain self-contained.

## VPN experience

VPN support is provider-neutral.

Focus supports protocols and adapter classes instead of hard-coding providers. Proton, Mullvad, NordVPN, enterprise OpenVPN, and custom WireGuard profiles are examples of configurations that can sit above generic adapters.

An approved VPN may connect or disconnect during a session when its policy allows it, but it must never bypass Focus filtering.

## Privileged actions

Focus uses a typed privileged-action model during locked sessions. Approved work operations may continue, while actions that would disable Focus are denied.

For example, connecting an approved WireGuard profile may be allowed while stopping the Focus daemon or replacing the Focus firewall policy is denied.

## Schedules

Focus supports:

- Manual sessions
- One-time scheduled sessions
- Recurring sessions

Scheduled sessions use the same locked-session rules as manual sessions.

## Emergency exit

Emergency exit is intentionally high-friction and requires all of the following:

1. A mandatory reason.
2. A fixed 10-minute delay.
3. A recovery code generated before the session is locked.

Emergency events are recorded in local history.

## History

History is informative rather than gamified. It shows completed sessions, durations, objectives, profiles, missed scheduled sessions, and emergency exits.

## Visual direction

Focus uses a custom startup-grade visual identity influenced by the precision of Linear and the keyboard-first polish of Raycast, but with less visual noise.

Design characteristics:

- Calm
- Precise
- Premium
- System-like
- Minimal
- Strong keyboard navigation
- Native-quality dark and light modes

A 4 px spacing grid anchors the design system.

## Privacy

Focus is local-first by default.

V1 requires no account, no cloud backend, no remote classifier, and no required personal telemetry. Full browsing history is not stored by default.

## V1 product scope

V1 includes:

- Linux system enforcement
- Desktop application
- Privileged daemon
- Profiles
- Manual and scheduled sessions
- Application blocking
- Firefox and Chromium protection
- Google filtering
- YouTube filtering
- Local classification
- Reboot recovery
- Network protection
- Generic VPN architecture
- Privileged operation control
- Emergency exit
- Local history

Windows and macOS are represented architecturally but not implemented as V1 system backends.

## Explicit non-goals for V1

- Cloud sync
- User accounts
- Mobile app
- Team administration
- Social features
- Leaderboards
- Complex streak systems
- Plugin marketplace
- General-purpose AI chatbot

## Product success criterion

Focus succeeds when a user can start a work session in a few interactions, keep legitimate development and study tools usable, lose access to distractions, use an approved VPN safely, reboot without escaping the session, and finish the session without spending time managing Focus itself.
