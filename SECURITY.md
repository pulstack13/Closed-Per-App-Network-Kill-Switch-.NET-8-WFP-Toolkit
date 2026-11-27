# Security Policy & Threat Model

## Privilege Boundaries
- **WFP Enforcement Requires Elevation:** Creating or modifying Windows Filtering Platform (WFP) provider, sublayer, and filter objects (`FwpmEngineOpen0` / `FwpmFilterAdd0`) requires local Administrator or `SYSTEM` privileges.
- **Unprivileged Operations:** Adapter enumeration (`GetAdaptersAddresses`), policy compilation (`WfpPlanCompiler`), and socket binding on user-owned sockets (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) run without elevation.
- **Protected System Processes:** `ProtectedProcessGuard` flags critical Windows processes (`csrss.exe`, `wininit.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `TrustedInstaller.exe`, `MsMpEng.exe`) and shared `svchost.exe` hosts to help prevent accidental OS networking disruption.

## Fail-Safe Behavior
- **Dynamic Sessions (`dynamicSession: true`):** Used by the desktop UI and CLI PoC commands so all temporary WFP filters are automatically purged by the Windows Base Filtering Engine (BFE) when the process exits.
- **Persistent Sessions (`dynamicSession: false`):** Designed for service/kill-switch scenarios where rules must remain active across crashes or reboots until explicitly removed.

## Scope & Honest Boundaries
- **User-Mode WFP Filtering vs. Route Steering:** User-mode WFP filters enforce fail-closed interface locking (blocking traffic routed over non-allowed interfaces). They do not override Windows' routing table for arbitrary unmodified third-party sockets; proxy-capable traffic can be explicitly steered via `AdapterBoundProxy`.
- **Local Administrator Threat Model:** A user-mode WFP manager cannot defend against a hostile local Administrator or `SYSTEM` process capable of modifying BFE filters.

## Reporting a Vulnerability
Please report security issues privately through GitHub Security Advisories rather than opening a public issue with exploit details.
