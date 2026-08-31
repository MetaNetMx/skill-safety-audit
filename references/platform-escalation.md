# Platform-Specific Escalation

Use this reference only when a candidate contains or remotely selects platform-specific artifacts. Static skill approval remains blocked until each applicable artifact is reviewed or removed.

Assign each platform a disposition: `APPLICABLE`, `NOT APPLICABLE`, or `INCONCLUSIVE`. Do not infer one platform's behavior from another.

## Windows

- Identify PE, DLL, driver, MSI/MSIX, PowerShell, batch, script-host, and embedded artifacts by content rather than extension.
- Review Authenticode coverage, signer continuity, installer custom actions, requested elevation, services, scheduled tasks, Registry persistence, DLL loading, credential access, process manipulation, defense evasion, and network destinations.
- Treat a valid signature as provenance evidence, not proof of safety.

## macOS

- Inspect Mach-O, app/pkg/dmg bundles, frameworks, XPC services, privileged helpers, and extensions.
- Review code signing, Team ID, notarization, entitlements, sandbox/hardened runtime, TCC resources, Keychain access, launchd/login persistence, dynamic loading, scripts, and network behavior.

## Linux

- Inspect ELF/shared objects, shell and language scripts, DEB/RPM/AppImage/Snap/Flatpak packages, hooks, and container definitions.
- Review RPATH/RUNPATH and preload behavior, setuid/setgid, capabilities, sudo/polkit, systemd/cron/autostart persistence, secret stores, `/proc`, kernel/eBPF behavior, container escape exposure, and network behavior.

## Android

- Inspect APK/AAB/split packages, signing continuity, manifest, DEX, native libraries, assets, and network-security configuration.
- Review exported components, permissions, Accessibility/VPN/device-admin/overlay services, storage and Keystore use, WebView bridges, dynamic code loading, background triggers, root dependency, obfuscation, and surveillance data flows.

## iOS/iPadOS

- Inspect IPA/app bundles, Mach-O, frameworks/extensions, Info.plist, signatures, provisioning profiles, and entitlements.
- Review privacy permissions, Keychain groups, pasteboard, app groups, extensions, MDM/configuration profiles, WKWebView bridges, background modes, private APIs, and jailbreak-only behavior separately from standard devices.

## Escalation evidence

For every artifact record:

`file hash → platform/architecture → signature/provenance → entry/trigger → privileges → persistence → data access → network destination → effect`

Do not execute the artifact on a personal or production device. Any dynamic analysis requires an approved disposable lab, synthetic data, restricted egress, snapshots, and a defined stop condition.
