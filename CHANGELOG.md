# Changelog

All notable changes to **Closed Per-App Network Kill-Switch & .NET 8 WFP Toolkit** are documented in this file.

## [0.1.0] - 2026-11-27

### Added
- **Core Policy Engine (`NetworkIsolation.Core`):** Fail-closed policy models (`Unassigned`, `Bind`, `AllowMultiple`, `BlockAll`), stable `NET_LUID` adapter descriptors, deterministic WFP provider/sublayer GUIDs, `WfpPlanCompiler`, and `ProtectedProcessGuard` for critical OS binaries.
- **Native Win32 WFP & IP Helper Library (`NetworkIsolation.Wfp`):**
  - `IpHelperAdapterProvider`: `GetAdaptersAddresses` adapter discovery with true `NET_LUID` identifiers, `ConvertInterfaceLuidToIndex`, and live interface/unicast IP change notifications (`NotifyIpInterfaceChange`, `NotifyUnicastIpAddressChange`).
  - `WfpEngineManager`: Transactional Base Filtering Engine (BFE) filter management across `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` with loopback exemptions, allowed-interface permits, and fail-closed base-block filters.
  - `AdapterBoundProxy` & `SocketNative`: Local HTTP `CONNECT` / SOCKS5 proxy and RFC 1035 direct DNS client using `IP_UNICAST_IF` / `IPV6_UNICAST_IF` socket interface pinning.
  - `TcpConnectionTerminator`: Active IPv4 TCP socket teardown helper via `GetExtendedTcpTable` and `SetTcpEntry`.
- **CLI Utility (`NetworkIsolation.Poc.Cli`):** Commands for `adapters`, `wfp-hold`, and `dns-probe`.
- **Desktop UI (`NetworkIsolation.UI`):** WPF (.NET 8) interface listing running GUI applications and active adapters with dynamic Apply/Remove WFP rule controls.
- **Automated Test Suite (`NetworkIsolation.Tests`):** xUnit coverage for x64 WFP ABI struct layouts, deterministic policy compilation, live IP Helper enumeration, adapter-bound proxy tunnels, DNS packet encoding/parsing, and Administrator-gated BFE smoke tests.
- **Documentation:** [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), [PROJECT_SPEC.md](PROJECT_SPEC.md), [TECHNICAL_RESEARCH.md](TECHNICAL_RESEARCH.md), [ROADMAP.md](ROADMAP.md), and [SECURITY.md](SECURITY.md).
