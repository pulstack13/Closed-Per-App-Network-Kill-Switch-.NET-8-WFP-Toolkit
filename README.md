# Closed Per-App Network Kill-Switch & .NET 8 WFP Toolkit

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6)](#prerequisites)
[![Runtime](https://img.shields.io/badge/.NET-8.0%20LTS-512BD4)](#prerequisites)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A **Windows Filtering Platform (WFP)** and **IP Helper** toolkit in pure **C# / .NET 8** for strict **fail-closed per-application network isolation** on Windows, paired with an **`IP_UNICAST_IF` / `IPV6_UNICAST_IF` adapter-bound local proxy** and **WPF desktop manager**.

> **Core Guarantee:** Lock an application to a specific network interface (such as Ethernet or a VPN adapter) so it **fails closed** rather than silently falling back to another interface (such as Wi-Fi or mobile tethering) if its allowed adapter disconnects or Windows selects a different route.

---

## Key Features

- **Strict Fail-Closed Per-App WFP Kill-Switch (`WfpEngineManager`):**
  - Installs transactional WFP rules inside a dedicated private sublayer (`FwpmTransactionBegin0` / `FwpmTransactionCommit0`) across IPv4 and IPv6 ALE layers (`ALE_AUTH_CONNECT_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6`).
  - Pairs explicit allowed-interface `PERMIT` rules (weight `10`) with a permanent base `BLOCK` filter (weight `1`) and optional loopback exemption (`127.0.0.0/8`, `::1/128`, weight `15`).
  - Supports both **dynamic sessions** (auto-cleanup when the app exits) and **persistent sessions** (survive crashes/reboots).
- **Zero-Dependency x64 .NET 8 Win32 P/Invoke (`NetworkIsolation.Wfp`):**
  - Clean `unsafe` / `[DllImport]` bindings to `fwpuclnt.dll`, `iphlpapi.dll`, `ws2_32.dll`, and `advapi32.dll` verified with x64 ABI struct layout tests.
  - Real `GetAdaptersAddresses` interface discovery keyed by persistent **`NET_LUID`** (not fragile adapter display names) plus `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange` real-time watchers.
  - Active IPv4 TCP socket teardown helper (`GetExtendedTcpTable` / `SetTcpEntry`) via `TcpConnectionTerminator`.
- **Adapter-Bound Local Proxy & Direct DNS (`AdapterBoundProxy`):**
  - Async loopback **HTTP `CONNECT`** and **SOCKS5** proxy whose outbound sockets explicitly pin `IP_UNICAST_IF` / `IPV6_UNICAST_IF` and bind to the target adapter's unicast IP.
  - Built-in RFC 1035 A/AAAA DNS client that sends queries directly to the bound adapter's DNS servers over adapter-pinned sockets.
- **CLI & WPF Desktop UI:**
  - `NetworkIsolation.Poc.Cli` for inspecting adapter LUIDs, testing direct adapter-bound DNS/TCP (`dns-probe`), and holding temporary WFP policies (`wfp-hold`).
  - `NetworkIsolation.UI` WPF application for listing visible running apps and active adapters with one-click dynamic Apply/Remove rules.
- **Critical Process Guardrails (`ProtectedProcessGuard`):**
  - Built-in safeguards and warnings for critical Windows processes (`csrss.exe`, `wininit.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `TrustedInstaller.exe`, `MsMpEng.exe`, and shared `svchost.exe`).

---

## Architecture & Scope

```text
+-------------------------------------------------------------------+
|  NetworkIsolation.UI (WPF .NET 8)  |  NetworkIsolation.Poc.Cli    |
+------------------------------------+------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------+
|  NetworkIsolation.Core                                            |
|  - PolicyMode (Unassigned | Bind | AllowMultiple | BlockAll)      |
|  - WfpPlanCompiler (deterministic filter planning)                |
|  - ProtectedProcessGuard                                          |
+------------------------------------+------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------+
|  NetworkIsolation.Wfp (Native Win32 P/Invoke)                     |
|  - WfpEngineManager        -> fwpuclnt.dll (BFE transactions)     |
|  - IpHelperAdapterProvider -> iphlpapi.dll (NET_LUID + events)    |
|  - AdapterBoundProxy       -> ws2_32.dll (IP_UNICAST_IF + DNS)    |
|  - TcpConnectionTerminator -> iphlpapi.dll (DELETE_TCB)           |
+-------------------------------------------------------------------+
```

### Important Technical Boundary (Filtering vs. Route Steering)
| Capability | Mechanism | Behavior |
| :--- | :--- | :--- |
| **Prevent Fallback / Kill-Switch** | User-mode WFP (`WfpEngineManager`) | **Enforced.** Blocks an app on any non-allowed adapter so traffic fails closed instead of leaking over another interface. |
| **Explicit Interface Steering** | `AdapterBoundProxy` (`IP_UNICAST_IF` / `IPV6_UNICAST_IF`) | **Supported for cooperating/proxy-configured apps.** Outbound proxy sockets bypass the default gateway metric to use the chosen adapter directly. |
| **Arbitrary Unmodified App Steering** | Requires signed Kernel WFP Callout Driver (`ALE_CONNECT_REDIRECT`) | Out of scope for this user-mode toolkit (see [TECHNICAL_RESEARCH.md](TECHNICAL_RESEARCH.md)). User-mode WFP filters authorize or block traffic after Windows route selection; they do not rewrite OS routing tables for arbitrary sockets. |

---

## Project Structure

```text
.
├── NetworkIsolation.sln
├── src/
│   ├── NetworkIsolation.Core/       # Policy models, WfpPlanCompiler, ProtectedProcessGuard
│   ├── NetworkIsolation.Wfp/        # Win32 P/Invoke (WFP, IP Helper, Socket, TCP teardown, Proxy)
│   ├── NetworkIsolation.Poc.Cli/    # CLI tool (adapters, wfp-hold, dns-probe)
│   └── NetworkIsolation.UI/         # WPF desktop UI for dynamic per-app WFP rules
├── tests/
│   └── NetworkIsolation.Tests/      # xUnit unit, ABI layout, live IP Helper, proxy, and BFE tests
├── ARCHITECTURE.md                  # System architecture, WFP weight tiers, and risk register
├── PROJECT_SPEC.md                  # Functional, security, and edge-case specifications
├── TECHNICAL_RESEARCH.md            # Deep dive into Windows WFP, routing, DNS, and driver signing
├── ROADMAP.md                       # Current capabilities and planned enhancements
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

---

## Prerequisites

- **OS:** Windows 10 (1809+) or Windows 11 (x64)
- **SDK:** [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- **Privileges:**
  - Building, running tests, listing adapters, and running `AdapterBoundProxy` require **no elevation**.
  - Installing/modifying WFP filters (`wfp-hold`, `dns-probe`, or clicking **Apply**/**Remove** in the WPF UI) requires running as **Administrator**.

---

## Quick Start

### 1. Build & Run Tests

```powershell
dotnet build NetworkIsolation.sln -c Release
dotnet test NetworkIsolation.sln
```

> Note: Elevated BFE smoke tests in `WfpElevatedSmokeTests` automatically skip when executed from a non-Administrator shell and run fully when `dotnet test` is executed in an elevated Administrator terminal.

### 2. Inspect Adapters & `NET_LUID` Identifiers (CLI)

```powershell
dotnet run --project src/NetworkIsolation.Poc.Cli -- adapters
```

### 3. Test Fail-Closed WFP Locking (Administrator Terminal)

Hold a temporary dynamic-session WFP policy locking an executable to a single adapter `NET_LUID` (rules automatically clear when the command exits or on `Ctrl+C`):

```powershell
dotnet run --project src/NetworkIsolation.Poc.Cli -- wfp-hold "C:\Windows\System32\curl.exe" 0x600800000000000 120
```

### 4. Test Direct Adapter-Bound DNS + TCP Connect (Administrator Terminal)

```powershell
dotnet run --project src/NetworkIsolation.Poc.Cli -- dns-probe 0x600800000000000 example.com 443
```

### 5. Launch the WPF Desktop App

```powershell
dotnet run --project src/NetworkIsolation.UI
```

Run as **Administrator** to enable **Apply** and **Remove** actions. All rules applied in the UI run inside a dynamic WFP session and clear automatically when the window closes.

---

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Sublayer design, filter weight hierarchy, DNS (`Dnscache`) notes, and risk register
- [TECHNICAL_RESEARCH.md](TECHNICAL_RESEARCH.md) — Windows routing vs. WFP timing, `ALE_BIND_REDIRECT` / `ALE_CONNECT_REDIRECT` findings, and driver-signing analysis
- [PROJECT_SPEC.md](PROJECT_SPEC.md) — Detailed functional requirements, edge cases, and validation scenarios
- [SECURITY.md](SECURITY.md) — Privilege model, fail-safe behavior, and responsible disclosure

---

## License

Released under the [MIT License](LICENSE).
