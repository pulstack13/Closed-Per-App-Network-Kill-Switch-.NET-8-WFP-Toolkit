# Roadmap

## Current Capabilities (v0.1.0)
- **Fail-Closed WFP Engine (`NetworkIsolation.Wfp`):** Per-executable IPv4/IPv6 ALE authorization filters (`ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`) in a private WFP sublayer with transactional updates and fail-closed base blocks.
- **Stable Interface Tracking:** `NET_LUID`-keyed adapter discovery and real-time OS change events via `iphlpapi.dll`.
- **Adapter-Bound Local Proxy (`AdapterBoundProxy`):** Reusable HTTP `CONNECT` / SOCKS5 proxy + direct RFC 1035 DNS resolver pinned via `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.
- **CLI & WPF Desktop App:** Inspection of live adapters/processes and temporary dynamic-session rule controls.

## Planned Enhancements
- **Windows Background Service:** `LocalSystem` Windows Service with boot-time persistent enforcement, atomic policy storage, and ACL-secured Named Pipe IPC.
- **UI Proxy Integration:** Expose per-app local proxy ports directly in `NetworkIsolation.UI` for proxy-aware browsers and tools.
- **Extended Coverage:** UWP/AppContainer `ALE_PACKAGE_ID` enforcement, `Dnscache` isolation modes, policy profiles, and Windows installer packaging.
- **Optional Signed Kernel Callout Driver:** Separate `ALE_CONNECT_REDIRECT` KMDF driver module (requires WDK + Microsoft Hardware Dev Center signing) for transparent non-proxy socket steering.
