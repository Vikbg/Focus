# Focus

Focus is a local-first, system-level focus environment for Linux that blocks distractions while preserving the tools needed for mathematics, physics, science, and programming.

## Status

Focus is in early development. The first target is Linux, with a cross-platform architecture designed for future Windows and macOS backends.

## Core principles

- Default deny during locked focus sessions
- Local-first privacy
- A privileged daemon is the security authority
- Firefox and Chromium filtering
- Approved VPNs without policy bypass
- Reboot-resistant sessions
- Fail-closed behavior for critical protection failures
- No cloud account required

## Development

The project is developed with Rust and TypeScript. The desktop application uses Tauri 2, React, Vite, and Tailwind CSS.

See `docs/superpowers/` for the validated product design, architecture, specification, and implementation plan.
