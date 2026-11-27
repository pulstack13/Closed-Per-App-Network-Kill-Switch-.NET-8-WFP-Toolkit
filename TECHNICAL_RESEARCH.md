# Windows Per-Application Network Isolation: Technical Research

**Scope:** Windows 10/11 desktop; strict policy means an app assigned to adapter A must never silently transmit via adapter B when A disappears. Research date: 2026-11-27.

## Executive verdict

Strict *fail-closed* per-application egress isolation is feasible without a custom driver: install persistent, narrowly scoped Windows Filtering Platform (WFP) filters and block the app unless the selected interface is the permitted interface. This can prevent fallback leaks, but does not force Windows to route an unbound socket through the selected adapter. If ordinary route selection chooses another adapter, the app's traffic fails closed instead of being steered.

Transparent adapter pinning for arbitrary, unmodified applications is not achievable with user-mode WFP management APIs alone. A kernel WFP callout can inspect ALE bind/connect operations and modify bind data / participate in redirection, but connect redirection is designed chiefly to redirect to a local proxy; it is not a general route override. A robust product should either (1) promise fail-closed interface allowlisting, with route/source-address setup as a usability aid, or (2) build and ship a signed callout driver plus carefully tested steering (often a per-app local proxy or explicit socket interface options). Never describe simple WFP block rules as “force bind.”

## Windows route and WFP timing

For an unbound socket, the application supplies a destination, not an outgoing interface. Windows TCP/IP performs route lookup using destination-prefix specificity and route/interface metrics, then selects a next hop/interface and an appropriate source address. IPv4/IPv6 route tables, address state, policy routes, VPNs, compartments, and interface metrics affect the choice. The strong/weak host model principally controls whether an address/interface accepts or emits traffic across interfaces; it is not an app-to-adapter binding mechanism. `IP_UNICAST_IF` and `IPV6_UNICAST_IF`, or binding to a local address, can influence a socket when the application cooperates.

WFP ALE authorization (`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`) is the outbound connection authorization point, not a request to change the route. At that point the classify data can include local/remote addresses and interface-related values where meaningful. Conditions such as `FWPM_CONDITION_INTERFACE_INDEX`, `FWPM_CONDITION_LOCAL_INTERFACE_INDEX`, `FWPM_CONDITION_IP_LOCAL_INTERFACE`, `FWPM_CONDITION_ALE_APP_ID`, and `FWPM_CONDITION_ALE_PACKAGE_ID` are predicates for filtering. They do not cause the route lookup to select the matching interface. In particular, an interface condition can be unavailable/not meaningful at an earlier ALE stage, or describe the chosen local/next-hop interface at the applicable layer; verify layer condition availability for each filter. A block on “all interfaces except A” catches an attempted fallback and blocks it; it does not retry routing over A.

A useful strict policy has a default block for that app's outbound traffic and a higher-priority permit conditioned on the desired interface (plus any deliberate loopback/DHCP/DNS exceptions). Ensure both IPv4 and IPv6 are covered and do not rely on an IPv4-only rule. WFP user-mode APIs (`FwpmEngineOpen0`, `FwpmTransactionBegin0`, `FwpmFilterAdd0`, `FwpmGetAppIdFromFileName0`, `FwpmSubLayerAdd0`) install/manage filters in the Base Filtering Engine. They are powerful policy controls but cannot call `bind()` on another process's sockets or mutate its routing decision.

## Enforcement mechanisms compared

| Mechanism | Can select interface for arbitrary app? | Can block fallback? | Main limits |
|---|---:|---:|---|
| User-mode WFP management (`Fwpm*`) | No | Yes | Filters classify; conditions do not rewrite socket state or route. Needs elevation/service and correct coverage. |
| Kernel WFP ALE callout | Potentially, with steering design | Yes | Driver engineering/signing; bind/connect redirect semantics are not a general interface selector. |
| `IP_UNICAST_IF` / `IPV6_UNICAST_IF` | Yes, for cooperating socket owner | N/A | Must be set per socket; cannot retrofit arbitrary third-party processes. |
| Bind to assigned local address | Often influences source/interface | N/A | Apps must cooperate; address can disappear/change; route and multihoming behavior still need validation. |
| DLL injection / API hooking | Sometimes | Not robust alone | Fragile, bypassable, incompatible with protected processes/mitigations, updates/architectures; avoid for production security boundary. |
| Winsock LSP | Legacy interception only | Not robust | Deprecated; compatibility and security issues; do not use for new products. |

WFP callout layers include `FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6`, `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, and authorization layers `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`; packet layers include `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6`. Management-plane layer GUID constants are declared in `fwpmu.h`; kernel classify counterparts use `FWPS_LAYER_*` in `fwpsk.h`. A callout is registered with `FwpsCalloutRegister1` or newer for redirect layers. Microsoft documents that connect/bind redirection redirects a connection to a proxy service; changing a flow's local address/port is supported only at bind-redirect, not connect-redirect. Redirect is supported for TCP, UDP, raw UDPv4 without header include, and raw ICMP, not all traffic. Thus a driver can implement app-aware steering, but the sound architecture is to either set a valid local address during bind redirection and enforce it, or redirect to a local proxy which creates its own socket with explicit interface selection. Proxying introduces protocol, UDP, DNS, loopback, and performance complexity.

At `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6`, packet filtering can identify selected interface/index and app-associated flow context where available, and drop prohibited packets. This is useful defense-in-depth, but packet filtering is late: it cannot make the prior route lookup choose the assigned adapter. ALE authorization is important because once a connection is authorized, ALE stateful filtering generally permits packets belonging to that flow absent policy change; dynamically changed policy must account for existing flows and reauthorization.

## Fail-closed behavior and disconnects

On adapter loss, Windows removes/invalidates routes and addresses; an unbound socket may choose another default route for a *new* connect or a later UDP send. An allow-only-A WFP policy must deny that traffic if it resolves to B. The safe failure is connection/network error, not fallback. Maintain the deny policy independently of adapter state; do not briefly remove filters while updating interface mappings.

Existing TCP flows are not magically migrated to another interface with their established tuple. They may stall, retransmit, or fail. If a policy change needs immediate revocation, block at ALE and/or transport and explicitly terminate tracked sockets/processes; WFP filters alone should not be assumed to synchronously close every established socket. UDP has no durable connection guarantee: connected UDP and unconnected `sendto` can perform route/interface selection per datagram and must be checked at ALE and packet layers. Re-authorize or classify each relevant send path; test socket reuse, wildcard binds, raw sockets and multicast separately.

Use a staged transition: keep app default-deny active; detect selected interface/address removal; invalidate mapping; allow only once the exact new interface identity is confirmed. Key interfaces by LUID/GUID plus current index, not friendly name or index alone; indices can change. Filtering should fail closed for unknown/zero/stale identity. Ensure policy survives service crash/restart (persistent WFP objects where appropriate) and define uninstall/recovery behavior.

## Traffic classes and hard cases

- **TCP:** ALE auth-connect is natural for process identity and new outbound connections; packet/flow controls address already-established flows and revocation. Existing sessions do not transparently move.
- **UDP:** ALE connect indications can occur for connected UDP and first outgoing datagram; unconnected `sendto` and subsequent destinations require coverage validation. Enforce at outbound transport as a backstop.
- **DNS (critical):** An app using Windows DNS Client APIs may submit queries to the local DNS Client service (`Dnscache`), whose network packets are emitted by a shared `svchost.exe`, not the requesting executable. App-ID-only filtering may therefore miss or misattribute the upstream DNS request. Windows DNS Client may also use configured DoH. Decide whether DNS is part of app isolation: options include blocking app DNS API access (usually impractical), configuring a per-interface resolver and applying a system-level DNS policy, or forcing app DNS through an app-aware local proxy. Do not allow all `svchost.exe` DNS through any interface as a casual exception. App-direct DNS over UDP/TCP 53 is attributable to the app and subject to its filters. App-direct DoT (commonly TCP 853) and DoH (HTTPS, commonly TCP 443; potentially HTTP/3 UDP 443) look like ordinary application traffic and must follow the app's interface rule. DNS over VPN/NRPT and encrypted resolver behavior need explicit testing.
- **IPv4/IPv6:** Install symmetric policy at V4 and V6 layers. IPv6 may remain usable when IPv4 adapter/address is unavailable; include SLAAC, DHCPv6, temporary/privacy addresses, link-local routes, and tunnel interfaces. Treat interface indices independently by family where required. Avoid accidentally permitting global IPv6 over Wi-Fi while IPv4 is blocked.
- **Link-local and multicast:** Link-local destinations need a scope/interface and can be legitimate on the assigned link; do not treat them as Internet egress. Explicitly specify policy for IPv4 169.254/16, IPv6 fe80::/10, multicast, DHCP/DHCPv6, router discovery, and neighbor discovery. These system-control packets may be emitted by OS services/components.
- **Loopback:** Usually exempt `127.0.0.0/8` and `::1` so local IPC/proxies work. This means a local proxy or helper may make network connections under its own identity; preserve original-app identity and prevent the proxy becoming an unrestricted tunnel. Decide whether LAN/private destinations and local network access count as allowed adapter traffic.

## Process identity, packages, and privileges

`FWPM_CONDITION_ALE_APP_ID` matches an executable device path obtained by `FwpmGetAppIdFromFileName0`; it is not a process ID and therefore covers that executable's instances. `FWPM_CONDITION_ALE_PACKAGE_ID` is the AppContainer/package SID and is necessary for packaged/UWP identity. Desktop child processes are separate executable identities; rules do not automatically mean “all descendants.” Electron browsers use multiple executables/process roles and may delegate networking to helpers. Define policy in terms of executable/package identities, and optionally maintain a process tree using ETW `Microsoft-Windows-Kernel-Process` or process notifications; WMI and Toolhelp snapshots are easier but have latency/race/coverage drawbacks. ALE app identity is stronger for packet attribution than periodic PID polling, but helper/service traffic can still be attributed to the helper.

A per-machine WFP policy service generally needs Administrator/SYSTEM-level rights to manage filters, and tamper-resistant product policy may require a protected service/appropriate ACLs. Admin/SYSTEM users and other firewall products can alter policy; a user-mode product is not a boundary against a hostile local administrator. Services often share `svchost.exe`, so executable identity may be too broad; service SID conditions and service-specific architecture may be needed. AppContainer package SIDs must be handled distinctly. WFP filters should use a private sublayer and explicit weights/permissions, and coexist with Windows Firewall/IPsec/third-party filters.

## Adapter and process observation APIs

- `GetAdaptersAddresses(AF_UNSPEC, ...)`: enumerate adapters, unicast addresses, LUID/index, operational state and friendly names; handle buffer resizing and transient changes.
- `ConvertInterfaceLuidToIndex` / `ConvertInterfaceIndexToLuid`: convert stable LUID identity and current IP Helper index.
- `NotifyIpInterfaceChange(AF_UNSPEC, callback, ..., initialNotification, &handle)`: asynchronous interface changes; unregister with `CancelMibChangeNotify2`.
- `NotifyUnicastIpAddressChange(AF_UNSPEC, callback, ..., initialNotification, &handle)`: address additions/removals/state changes, likewise cancel registration.
- Process observation: ETW provider `Microsoft-Windows-Kernel-Process` for starts/stops; WMI (`Win32_ProcessStartTrace`) or Toolhelp are alternatives. Polling has race windows; monitor new processes before allowing their first outbound traffic if implementing an app/process policy. WFP ALE app/package identity should remain the enforcement source of truth.

## Production architecture recommendation

**Recommended first production architecture:** elevated Windows service + user-mode WFP dynamic/persistent policy, with per-app default-deny for outbound V4/V6 and explicit allow only on the selected interface; add packet-layer blocks as defense-in-depth. Manage policy transactionally, use app/package identity, exempt loopback narrowly, and continuously monitor adapter and address changes. This delivers an honest and useful product guarantee: “traffic is blocked when it cannot use the selected adapter.” It does not guarantee that arbitrary apps are transparently routed via it. Pair with optional route metric/interface selection and app guidance, but regard these as convenience, not enforcement.

**If transparent steering is a hard requirement:** build a kernel WFP callout driver and likely a local per-app proxy or carefully validated ALE bind-redirection strategy, then retain user-mode WFP fail-closed filters as a safety net. Test all app socket patterns, v4/v6, UDP, DNS, loopback, VPN, sleep/resume, fast user switching, and adapter churn. Driver code must be signed for retail Windows: on Windows 10 1607+ (including Windows 11), new kernel drivers need Microsoft Hardware Dev Center signing; EV certificate is needed for dashboard submission. WHQL/WHCP HLK testing is the recommended broadly distributable production route; attestation signing is principally for testing and is not Windows-certified/retail Windows Update distribution. Test signing requires test configuration and is not a consumer deployment solution. This engineering, certification, support, and security burden is substantial.

## Key references (Microsoft)

- [WFP filtering condition identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
- [WFP ALE stateful filtering](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering)
- [Using bind or connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [WFP layer requirements and restrictions](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-layer-requirements-and-restrictions)
- [IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
- [IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/WinSock/ipproto-ipv6-socket-options)
- [Kernel-mode code signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [Driver signing options and best practices](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)
- [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
- [NotifyIpInterfaceChange](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)
- [NotifyUnicastIpAddressChange](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)
- [ConvertInterfaceLuidToIndex](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex)

## Bottom line

Strict no-fallback isolation is feasible as **fail-closed filtering**. Transparent forced interface selection for arbitrary third-party processes requires a substantially more complex kernel/proxy strategy and cannot be honestly promised by a user-mode WFP rules manager alone. DNS Client service attribution, IPv6, UDP sendto, existing flows, helper processes, and Microsoft driver signing are the decisive engineering risks.
