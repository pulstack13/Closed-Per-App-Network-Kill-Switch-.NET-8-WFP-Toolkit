# Windows Per-Application Network Manager - Specification

## Executive Summary

This document specifies a production-grade Windows application that enforces **strict per-application network isolation** at the kernel/driver level. The core requirement is fail-closed network binding: when an application is bound to a specific network adapter (e.g., Ethernet), it must NEVER silently fall back to another adapter (e.g., Wi-Fi) if the bound adapter becomes unavailable. Instead, the application's network access must be blocked until the bound adapter returns or the user explicitly changes the policy.

---

## 1. Core Functional Requirements

### 1.1 Network Adapter Management

#### FR-1.1.1: Adapter Discovery and Enumeration
- **Requirement**: The system MUST enumerate all active and inactive network adapters on the system.
- **Adapters Supported**:
  - Physical Ethernet adapters
  - Wi-Fi (WLAN) adapters
  - USB tethering adapters (RNDIS, NCM)
  - VPN adapters (WireGuard, OpenVPN, IPSec, etc.)
  - Virtual adapters (Hyper-V, VMware, VirtualBox)
  - Bluetooth PAN adapters
  - Mobile broadband (WWAN/LTE) adapters
  - Any other NDIS-compliant network interface

#### FR-1.1.2: Stable Adapter Identification
- **Requirement**: Adapters MUST be identified using **stable, persistent identifiers** that survive reboots, driver updates, and physical reconnections.
- **Implementation Requirements**:
  - Primary identifier: **Interface LUID** (Locally Unique Identifier) - stable across reboots
  - Secondary identifier: **Interface GUID** - persistent network interface identifier
  - Fallback identifier: Device Instance Path (for hardware tracking)
  - Display Name: User-friendly name (e.g., "Ethernet 2") - stored for UI display but NEVER used as the primary identifier due to mutability
- **Edge Cases**:
  - USB adapters that get different port assignments → LUID remains stable
  - Renamed adapters (user changes "Ethernet" to "LAN") → LUID/GUID unchanged
  - Driver reinstall → LUID/GUID preserved
  - Hardware replacement (same model) → new LUID/GUID, requires user to reassign policies
#### FR-1.1.3: Adapter State Monitoring
- **Requirement**: The system MUST continuously monitor the state of all network adapters in real-time.
- **States to Track**:
  - Connected/Disconnected (cable unplugged, Wi-Fi out of range)
  - Enabled/Disabled (adapter disabled in Windows settings)
  - Media type (Ethernet, 802.11, WWAN, etc.)
  - Link speed and duplex
  - IP address assignment status (IPv4/IPv6)
  - Default gateway presence
  - Internet connectivity (optional, for status display)
- **Change Detection**: State changes MUST trigger immediate policy re-evaluation for affected applications.

#### FR-1.1.4: Adapter Priority and Metrics
- **Requirement**: The system MUST respect Windows adapter metrics and routing priorities when multiple adapters are allowed for an application.
- **Behavior**: When an application is assigned multiple allowed adapters, Windows' own routing table metric determines which adapter is preferred (lower metric = higher priority).

---

### 1.2 Application Identification and Assignment

#### FR-1.2.1: Application Identification Methods
- **Requirement**: Applications MUST be uniquely and reliably identified for policy enforcement.
- **Primary Identifier**: Full executable path (case-insensitive, normalized)
  - Example: `C:\Program Files\Mozilla Firefox\firefox.exe`
  - Normalization: Resolve symlinks, expand environment variables, convert to lowercase
- **Secondary Identifiers** (for enhanced security):
  - Authenticode signature (publisher, certificate thumbprint)
  - File hash (SHA-256) for unsigned executables
  - UWP Package Family Name (for packaged apps)
  - Windows Service Name (for services)

#### FR-1.2.2: Running Process Detection
- **Requirement**: The system MUST detect all running instances of assigned applications.
- **Detection Methods**:
  - Process enumeration via Windows API (EnumProcesses, CreateToolhelp32Snapshot)
  - Query process image path (GetModuleFileNameEx, QueryFullProcessImageName)
  - Match against stored policies using normalized paths
- **Real-Time Monitoring**: New process creation MUST be detected within 1 second for immediate policy application.

#### FR-1.2.3: Multi-Instance and Multi-Process Applications
- **Requirement**: Applications that spawn multiple processes (browsers, Electron apps, IDEs) MUST be handled correctly.
- **Child Process Inheritance**:
  - **Default Behavior**: Child processes inherit the parent's network policy
  - **Implementation**: Enforce policy on the entire process tree rooted at the assigned executable
  - **Edge Cases**:
    - Browser tabs/renderers (Chrome, Edge, Firefox multi-process) ? inherit browser policy
    - Electron apps (Slack, Discord, VS Code) ? all renderer processes inherit policy
    - Launchers that spawn game clients (Steam, Epic) ? option to enforce on launcher OR on child game executable
- **Multiple Instance Handling**:
  - All instances of the same executable path receive the same policy
  - Per-instance policies NOT supported (would be ambiguous and complex)

#### FR-1.2.4: UWP and Packaged Applications
- **Requirement**: Universal Windows Platform (UWP) apps and MSIX-packaged apps MUST be supported.
- **Identification**: Use Package Family Name (e.g., `Microsoft.WindowsStore_8wekyb3d8bbwe`)
- **Detection**: Query app container SID and package information
- **Enforcement**: Apply policy to all processes in the app container

#### FR-1.2.5: Windows System Services Safeguards
- **Requirement**: The system MUST prevent users from accidentally breaking critical Windows services.
- **Protected Services** (Warning or Block):
  - `svchost.exe` (unless specific service instance is targeted with advanced mode)
  - `wininit.exe`, `csrss.exe`, `lsass.exe`, `services.exe` (critical system processes)
  - `TrustedInstaller.exe`, `MsMpEng.exe` (Windows Update, Defender)
  - `dllhost.exe`, `RuntimeBroker.exe` (generic host processes)
- **UI Behavior**:
  - Show warning dialog: "Restricting this system process may break Windows functionality. Continue only if you know what you're doing."
  - Provide option to exclude system processes from assignment list by default (user preference)

---

### 1.3 Network Policy Modes

#### FR-1.3.1: Policy Mode Definitions

**Mode 1: Unassigned (System Default)**
- Application has no policy assigned
- Uses Windows' default routing behavior (all adapters, metric-based routing)
- No restrictions applied

**Mode 2: Bind to Specific Adapter (Strict, Fail-Closed)**
- Application is bound to exactly ONE network adapter
- **Enforcement**:
  - All network traffic MUST route through the bound adapter
  - If bound adapter is disconnected/disabled/unavailable:
    - **New connections**: Blocked (connection fails immediately)
    - **Existing connections**: Terminated gracefully (RST for TCP, dropped for UDP)
    - **DNS resolution**: Blocked (or uses bound adapter's DNS only, no fallback)
  - NO silent fallback to other adapters under any circumstances
- **Recovery**: When bound adapter becomes available again:
  - Policy re-applied automatically
  - Application can establish new connections immediately
  - User notification (optional): "Adapter [Name] reconnected, [App] network access restored"

**Mode 3: Allow Multiple Selected Adapters (Restricted Failover)**
- Application is allowed to use a **predefined set of adapters only**
- **Enforcement**:
  - Application can connect through any adapter in the allowed set
  - Windows routing metrics determine preference within the allowed set
  - Adapters NOT in the allowed set are blocked (strict deny-list)
  - If all allowed adapters are unavailable: fail-closed (no fallback)
- **Use Case**: "Allow app to use Ethernet OR Wi-Fi, but never VPN" (privacy/security)

**Mode 4: Block All Network**
- Application is completely blocked from all network access
- **Enforcement**:
  - All connection attempts fail immediately
  - Loopback/localhost (127.0.0.1, ::1) MAY be exempted (user preference, default: exempt)
- **Use Case**: Sandbox untrusted applications, prevent telemetry, offline mode enforcement

#### FR-1.3.2: Policy Persistence
- **Requirement**: Policies MUST persist across:
  - Application restarts
  - System reboots
  - User logoff/logon
  - Adapter reconnection
  - Windows updates
- **Storage**: Policies stored in a secure, structured configuration file (JSON or SQLite database in `C:\ProgramData\NetworkManager\policies.db`)
- **Backup**: Automatic backup of policy database before modifications

---

### 1.4 Protocol and Traffic Handling

#### FR-1.4.1: Supported Network Protocols
- **TCP**: Full support (connection tracking, graceful termination on adapter loss)
- **UDP**: Full support (stateless blocking, per-packet enforcement)
- **ICMPv4/ICMPv6**: Support for ping, traceroute (optional, user-configurable)
- **IPv4**: Full support
- **IPv6**: Full support (including link-local, ULA, and global addresses)

#### FR-1.4.2: DNS Resolution Handling
- **Challenge**: Windows DNS Client service (`dnscache`) is shared by all applications.
- **Requirement**: DNS queries MUST respect per-application adapter binding.
- **Implementation Strategy**:
  - **Option A** (Preferred): Intercept DNS queries at the socket layer, force queries through bound adapter's DNS servers only
  - **Option B**: Use Windows Filtering Platform (WFP) to redirect DNS packets (port 53 TCP/UDP) per-application
  - **Fallback Behavior**: If DNS resolution fails due to adapter binding, do NOT fall back to other adapters' DNS
- **Edge Case**: DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) ? treated as HTTPS/TLS traffic, subject to same binding rules

#### FR-1.4.3: Loopback and Localhost Traffic
- **Requirement**: Loopback traffic (127.0.0.0/8 for IPv4, ::1 for IPv6) MUST NOT be blocked by adapter binding policies.
- **Rationale**: Many applications use localhost for inter-process communication (IPC), databases, local servers. Blocking would break functionality unexpectedly.
- **Implementation**: Explicitly exempt loopback interface (Interface LUID for loopback) from policy enforcement.
- **User Override**: Advanced setting to block loopback if explicitly desired (default: allow).

#### FR-1.4.4: LAN vs WAN Traffic Differentiation
- **Requirement**: The system SHOULD allow policies to differentiate between local network (LAN) and internet (WAN) traffic.
- **Implementation** (Optional, Phase 2):
  - Detect private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local)
  - Option: "Block internet but allow LAN" mode
  - Option: "Route LAN through Ethernet, internet through VPN"
- **Initial Release**: Treat all non-loopback traffic equally (no LAN/WAN distinction).

#### FR-1.4.5: Active Socket Handling on Adapter Loss
- **Requirement**: When a bound adapter disconnects, existing active connections MUST be handled gracefully.
- **TCP Connections**:
  - Send RST (reset) packets to terminate connections immediately, OR
  - Allow connections to timeout naturally (if adapter might return soon)
  - User preference: "Immediate termination" vs "Wait for timeout"
- **UDP Sockets**:
  - Drop all outgoing packets
  - Incoming packets ignored (firewall-like behavior)
- **User Notification**: Optional notification when connections are terminated due to adapter loss.

---

### 1.5 Disconnection and Recovery Behavior

#### FR-1.5.1: Adapter Disconnection Detection
- **Requirement**: The system MUST detect adapter disconnection within 2 seconds (maximum).
- **Detection Methods**:
  - Network interface state change notifications (WFP callbacks, NdisMediaConnectState)
  - Poll adapter status if events are missed (fallback, 1-second interval)
- **Immediate Action**: Apply fail-closed policy to all affected applications immediately.

#### FR-1.5.2: Adapter Reconnection and Recovery
- **Requirement**: When a disconnected adapter reconnects, policies MUST be re-applied automatically without user intervention.
- **Reconnection Detection**:
  - Media connect event
  - IP address assignment (DHCP completion)
- **Re-Application**: Resume enforcing policy for all applications bound to the reconnected adapter.
- **User Notification**: Optional toast notification: "Network adapter [Name] reconnected."

#### FR-1.5.3: Startup and Boot-Time Enforcement
- **Requirement**: Policies MUST be enforced BEFORE user logon to prevent network leaks during boot.
- **Implementation**:
  - Backend service starts automatically at system boot (not user logon)
  - Service starts with Windows (Early Launch Anti-Malware boot driver phase, if feasible)
  - Apply policies as soon as network stack initializes
- **Edge Case**: Applications that auto-start before service is ready ? queue policy application, enforce immediately when service starts (acceptable brief window < 5 seconds).

#### FR-1.5.4: Fail-Safe Behavior on Service Crash
- **Requirement**: If the backend enforcement service crashes, the system MUST default to a SAFE state.
- **Safe State Options** (User-Configurable):
  - **Option A** (Default): Block all previously-restricted applications (fail-closed, secure)
  - **Option B**: Remove restrictions, allow normal routing (fail-open, usable but insecure)
- **Implementation**: Use persistent WFP filters that remain active even if the service crashes. Service removal explicitly clears filters.

---

## 2. Backend Architecture Requirements

### 2.1 Windows Service (Backend Enforcement Engine)

#### NFR-2.1.1: Service Characteristics
- **Type**: Windows Service (`sc.exe`, LocalSystem or LocalService account)
- **Startup**: Automatic (Delayed Start acceptable, but boot-time enforcement requires Automatic)
- **Privileges**: Administrator/SYSTEM required for WFP filter management and low-level network interception
- **Dependencies**: 
  - Base Filtering Engine (BFE) service
  - Network Store Interface Service (NSI)

#### NFR-2.1.2: Enforcement Mechanism
- **Technology**: Windows Filtering Platform (WFP) for kernel-level packet filtering
- **WFP Layers** (Primary):
  - `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`: Outbound connection authorization
  - `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`: Inbound connection authorization
  - `FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6`: Socket binding redirection (force bind to specific adapter)
- **WFP Callout Driver** (Advanced, if needed):
  - Custom kernel driver for deep packet inspection or complex routing logic
  - Initial release: User-mode WFP filters sufficient for most policies

#### NFR-2.1.3: Policy Engine
- **Responsibilities**:
  - Load policy database on startup
  - Match running processes to policies in real-time
  - Apply/update/remove WFP filters dynamically
  - Monitor adapter state changes and trigger re-evaluation
- **Performance**: Policy lookup MUST complete in < 10ms per process (use hash tables, indexed database)

#### NFR-2.1.4: Inter-Process Communication (IPC)
- **Requirement**: GUI and service MUST communicate via secure, low-latency IPC.
- **Mechanism**: Named pipes, Windows RPC, or localhost TCP socket (authenticated)
- **Security**: Only Administrator users or processes with correct token can send policy updates to service
- **API Operations**:
  - Get current policies
  - Add/update/delete policy for an application
  - Get list of running processes and their enforced policies
  - Get adapter list and states
  - Subscribe to real-time events (adapter state changes, policy violations)

---

### 2.2 Policy Storage and Configuration

#### NFR-2.2.1: Configuration File Format
- **Format**: JSON or SQLite database
- **Location**: `C:\ProgramData\NetworkManager\` (system-wide, protected by NTFS permissions)
- **Permissions**: 
  - Read: Administrators, SYSTEM
  - Write: Administrators only
  - Deny: Standard users (prevents tampering)

#### NFR-2.2.2: Policy Schema
Each policy entry contains:
```json
{
  "id": "unique-guid",
  "appType": "executable" | "uwp" | "service",
  "appPath": "C:\\Program Files\\App\\app.exe",
  "packageFamilyName": "...",
  "serviceName": "...",
  "signature": {
    "publisher": "CN=Publisher",
    "thumbprint": "sha256-hash"
  },
  "policyMode": "bind" | "allow-multiple" | "block-all" | "unassigned",
  "allowedAdapters": [
    "{LUID-1}",
    "{LUID-2}"
  ],
  "options": {
    "allowLoopback": true,
    "terminateOnDisconnect": false,
    "notifyOnBlock": true
  },
  "createdAt": "2024-01-15T10:30:00Z",
  "modifiedAt": "2024-01-20T14:45:00Z"
}
```

#### NFR-2.2.3: Backup and Recovery
- **Requirement**: Automatic backup before every policy modification.
- **Backup Location**: `C:\ProgramData\NetworkManager\backups\policies_YYYYMMDD_HHMMSS.json`
- **Retention**: Keep last 10 backups, auto-delete older
- **UI Feature**: Restore from backup in case of misconfiguration


---

## 3. GUI Application Requirements

### 3.1 Adapter Dashboard

#### FR-3.1.1: Adapter List View
- **Display**: Tabular or card-based view of all network adapters
- **Columns/Fields**:
  - Adapter name (user-friendly, e.g., "Wi-Fi", "Ethernet 2")
  - Type (Ethernet, Wi-Fi, VPN, USB Tethering, etc.)
  - Status (Connected/Disconnected, Enabled/Disabled)
  - IP Address (IPv4 and IPv6)
  - Link speed (e.g., "1 Gbps", "866 Mbps")
  - Assigned apps count (e.g., "3 apps using this adapter")
- **Real-Time Updates**: Adapter list updates automatically when adapters are added/removed/state changes (no manual refresh needed)

#### FR-3.1.2: Adapter Details Panel
- **Trigger**: Click on an adapter in the list
- **Display**:
  - Full adapter properties (MAC address, MTU, DNS servers, default gateway)
  - List of applications currently assigned to this adapter
  - Historical stats (optional): bytes sent/received, uptime

---

### 3.2 Application Assignment Controls

#### FR-3.2.1: Application List View
- **Display**: List of all applications with assigned policies (default: show assigned apps only; option to show all running apps)
- **Columns/Fields**:
  - Application name (derived from executable name or display name)
  - Executable path (truncated, with tooltip for full path)
  - Policy mode (icon or badge: "Bound to Ethernet", "Restricted", "Blocked")
  - Current status (icon: connected, disconnected, blocked)
  - Running instances count
- **Filter/Search**: Search by app name or path; filter by policy mode

#### FR-3.2.2: Assign Application to Adapter
- **Trigger**: Click "Add Application" or "Assign" button
- **UI Flow**:
  1. **Select Application**:
     - Option A: Choose from running processes (dropdown or searchable list)
     - Option B: Browse for executable file (file picker)
     - Option C: Enter path manually
     - Option D: Select UWP app from installed package list
  2. **Select Policy Mode**: Radio buttons or dropdown:
     - Bind to specific adapter (then choose adapter from list)
     - Allow multiple adapters (then multi-select adapters)
     - Block all network
  3. **Configure Options** (Expandable section):
     - Allow loopback (checkbox, default: checked)
     - Terminate connections on disconnect (checkbox, default: unchecked)
     - Show notifications on block (checkbox, default: checked)
  4. **Apply**: Save policy and enforce immediately
- **Validation**: Warn if assigning a system-critical process (see FR-1.2.5)

#### FR-3.2.3: Edit/Remove Policy
- **Edit**: Click on existing policy, modify settings in same UI as "Assign"
- **Remove**: Right-click ? "Remove Policy" or dedicated "Remove" button, with confirmation dialog
- **Bulk Operations**: Multi-select applications, apply policy to all (optional, Phase 2)

---

### 3.3 Connection Status and Monitoring

#### FR-3.3.1: Real-Time Status Indicators
- **Requirement**: User MUST see the current enforcement status at a glance.
- **Status Icons** (per application):
  - Green check: Application is connected through allowed adapter(s)
  - Yellow warning: Application's bound adapter is disconnected, connections blocked (fail-closed)
  - Red block: Application is blocked by policy (Block All mode)
  - Gray: Application not running
- **System Tray Icon**: Shows overall status (normal, some apps blocked, service error)

#### FR-3.3.2: Activity Log
- **Display**: Scrollable log of recent enforcement events
- **Log Entries**:
  - Timestamp
  - Application name
  - Event type (Policy applied, Connection blocked, Adapter disconnected, Policy violated)
  - Details (e.g., "firefox.exe: Blocked connection to 192.0.2.1:443 (Ethernet disconnected)")
- **Filters**: Filter by application, event type, time range
- **Export**: Export log to CSV or text file
- **Retention**: Keep logs for 7 days (configurable, 1-30 days)

#### FR-3.3.3: Notifications (Toast/Tray)
- **Requirement**: User MAY opt-in to receive notifications for key events.
- **Notification Types** (User-Configurable):
  - Adapter disconnected/reconnected
  - Application blocked due to policy (first occurrence only, avoid spam)
  - Policy violation attempt detected
  - Service error or crash
- **UI**: Windows toast notifications (Action Center integration)
- **Preference**: Global on/off, per-event-type toggles in settings

---

### 3.4 Profiles (Optional, Phase 2)

#### FR-3.4.1: Policy Profiles
- **Feature**: Save and load sets of policies as named profiles (e.g., "Home", "Office VPN", "Public Wi-Fi").
- **Use Case**: Quickly switch between different network scenarios without manually reassigning each app.
- **Implementation**: Profile is a snapshot of current policy database; applying a profile replaces active policies.

---

## 4. Security and Integrity Requirements

### 4.1 Enforcement Integrity

#### NFR-4.1.1: No UI-Only Enforcement
- **Requirement**: Policies MUST be enforced at the kernel or driver level, NOT merely in the GUI.
- **Validation**: Even if GUI is closed or uninstalled, backend service continues to enforce policies.
- **Attack Resistance**: Malicious applications cannot bypass enforcement by killing the GUI process.

#### NFR-4.1.2: No Silent Fallback
- **Requirement**: The system MUST NEVER allow an application to silently fall back to a non-allowed adapter.
- **Testing**: Explicit test cases:
  - Bind app to Ethernet, unplug cable ? app cannot connect (verified with packet capture)
  - Bind app to Wi-Fi, disable Wi-Fi ? app cannot connect via Ethernet (verified)
  - Allow app on Ethernet+Wi-Fi only, connect VPN ? app cannot use VPN (verified)

#### NFR-4.1.3: Tamper Resistance
- **Requirement**: Policy database and service configuration MUST be protected from tampering by non-admin users.
- **Implementation**:
  - NTFS permissions: Administrators/SYSTEM only
  - Service protection: Set `SERVICE_CONFIG_FAILURE_ACTIONS` to restart on crash
  - Code signing: Service executable and driver (if any) must be Authenticode-signed

#### NFR-4.1.4: Fail-Safe Behavior
- **Requirement**: If the enforcement mechanism fails (service crash, driver unload), the system MUST default to a safe state (see FR-1.5.4).
- **Testing**: Manually stop service ? verify that restricted apps remain blocked or switch to configured fail-safe mode.

---

### 4.2 Safe Defaults

#### NFR-4.2.1: Never Brick Critical System Functions
- **Requirement**: Default configuration MUST NOT break Windows Update, Windows Defender, or critical system services.
- **Implementation**:
  - Maintain internal exclusion list of protected processes (updatable)
  - Warn user before assigning policies to excluded processes
  - Option: "Advanced Mode" to override exclusions (requires confirmation)

#### NFR-4.2.2: First-Run Experience
- **Requirement**: On first launch, the system has NO policies assigned (all apps use system default routing).
- **Rationale**: Avoids unintentional breakage; user explicitly assigns policies.
- **Optional**: First-run wizard offering common presets (e.g., "Route browsers through VPN", "Restrict torrents to Ethernet").

---

## 5. Non-Functional Requirements

### 5.1 Performance

#### NFR-5.1.1: Minimal Overhead
- **Requirement**: Network throughput degradation MUST be < 5% compared to unrestricted Windows routing.
- **Latency**: Added latency per packet MUST be < 1ms (measured at WFP layer).
- **CPU Usage**: Service idle CPU usage MUST be < 1% on modern hardware (4-core CPU or better).

#### NFR-5.1.2: Scalability
- **Requirement**: The system MUST handle at least 100 concurrent applications with assigned policies without performance degradation.
- **Policy Lookup**: O(log N) or O(1) lookup time (hash table or indexed database).

---

### 5.2 Reliability

#### NFR-5.2.1: Service Uptime
- **Requirement**: Backend service MUST maintain > 99.9% uptime during normal system operation.
- **Auto-Recovery**: Service automatically restarts on crash (Windows SCM failure actions).

#### NFR-5.2.2: Data Integrity
- **Requirement**: Policy database MUST be crash-resistant (atomic writes, transaction support if using SQLite).
- **Backup**: Automatic backups prevent data loss from corruption.

---

### 5.3 Usability

#### NFR-5.3.1: Intuitive UI
- **Requirement**: Non-technical users MUST be able to assign applications to adapters without reading documentation.
- **Design Principles**:
  - Clear, non-technical language (avoid "LUID", "WFP", "callout driver")
  - Visual adapter and app selection (icons, colors)
  - Tooltips and help text for advanced options
  - Confirmation dialogs for destructive actions (remove policy, block system process)

#### NFR-5.3.2: Accessibility
- **Requirement**: GUI MUST be accessible to users with disabilities.
- **Implementation**:
  - Keyboard navigation (tab order, shortcuts)
  - Screen reader support (ARIA labels, accessible names)
  - High-contrast mode support
  - Scalable UI (DPI-aware, font size adjustments)

---

### 5.4 Compatibility

#### NFR-5.4.1: Windows Versions
- **Requirement**: Support Windows 10 (version 1809 or later) and Windows 11.
- **Rationale**: WFP APIs are mature and stable in these versions.
- **Testing**: Test on Windows 10 21H2, Windows 10 22H2, Windows 11 21H2, Windows 11 22H2.

#### NFR-5.4.2: Coexistence with Firewalls and Security Software
- **Requirement**: The system MUST coexist with Windows Defender Firewall, third-party firewalls (Norton, Kaspersky), and VPN clients.
- **WFP Layer Coordination**: Use appropriate WFP sublayers and weights to avoid conflicts.
- **Testing**: Test with common security software installed (Windows Defender, Malwarebytes, NordVPN).


---

## 6. Edge Cases and Special Scenarios

### 6.1 Multi-Homed Systems
- **Scenario**: System with multiple active adapters (Ethernet + Wi-Fi + VPN all connected).
- **Requirement**: Policies MUST enforce correctly regardless of Windows' routing table metric priorities.
- **Test**: Bind app to lowest-priority adapter ? verify traffic uses that adapter, not higher-priority one.

### 6.2 Adapter Hot-Swapping
- **Scenario**: User unplugs Ethernet, plugs in different Ethernet adapter (new hardware, new LUID).
- **Requirement**: Policies bound to old adapter MUST remain bound to old adapter (no automatic re-binding).
- **UI**: Show warning "Bound adapter [Old Name] is no longer present. Reassign policy?"

### 6.3 Hyper-V and Virtual Machines
- **Scenario**: Hyper-V creates virtual adapters; VMs may have their own network policies.
- **Requirement**: Host policies do NOT affect VM traffic (VMs use Hyper-V virtual switch, different network stack).
- **UI**: Clearly label virtual adapters (e.g., "vEthernet (Default Switch)") to avoid confusion.

### 6.4 VPN Split-Tunneling Interaction
- **Scenario**: VPN client configured for split-tunneling (some traffic through VPN, some through physical adapter).
- **Requirement**: Application bound to physical adapter MUST NOT use VPN, even if VPN is active.
- **Test**: Bind app to Ethernet, start VPN with split-tunnel ? verify app traffic does NOT go through VPN tunnel.

### 6.5 Windows Subsystem for Linux (WSL2)
- **Scenario**: WSL2 uses Hyper-V virtual networking (vEthernet).
- **Requirement**: Policies do NOT apply to WSL2 Linux processes (Linux kernel, different network stack).
- **Optional**: Provide guidance for users who want to route WSL2 traffic (modify WSL2 network config, out of scope for this tool).

### 6.6 Application Updates and Path Changes
- **Scenario**: Application updates, executable moves from `Program Files\App\v1\app.exe` to `Program Files\App\v2\app.exe`.
- **Requirement**: Policy bound to old path MUST NOT automatically apply to new path (security risk).
- **UI**: Detect executable path change (via signature matching), prompt user: "App.exe has updated. Apply existing policy to new version?"

### 6.7 Metered Connections
- **Scenario**: Windows marks an adapter as "metered" (mobile hotspot, limited data).
- **Requirement**: Policies MUST still enforce; metered status does NOT override policy.
- **Optional**: UI indicator showing which adapters are metered (informational only).

### 6.8 Network Bridge
- **Scenario**: User creates a Windows network bridge combining two adapters.
- **Requirement**: Policies apply to the bridge interface, not individual bridged adapters.
- **UI**: Show bridge as a separate adapter type.

---

## 7. User Stories and Acceptance Criteria

### User Story 1: Privacy-Conscious User
**As a** privacy-conscious user,  
**I want to** bind my torrent client exclusively to my VPN adapter,  
**So that** my ISP never sees torrent traffic, even if the VPN disconnects.

**Acceptance Criteria**:
- AC-1: User can select torrent client executable (e.g., qBittorrent) and bind it to VPN adapter.
- AC-2: When VPN adapter is connected, torrent client can download/upload normally.
- AC-3: When VPN adapter disconnects (VPN crash, disconnect), torrent client's connections are immediately terminated.
- AC-4: Torrent client CANNOT connect through Ethernet or Wi-Fi, even though those adapters are active.
- AC-5: User receives notification when VPN disconnects and torrent client is blocked.
- AC-6: When VPN reconnects, torrent client can resume connections immediately.

### User Story 2: Remote Worker
**As a** remote worker,  
**I want to** bind Microsoft Teams and Outlook to my Ethernet adapter,  
**So that** work communication is reliable and doesn't use my limited mobile hotspot data when Ethernet is available.

**Acceptance Criteria**:
- AC-1: User can assign Teams and Outlook to Ethernet adapter.
- AC-2: While Ethernet is connected, Teams/Outlook use Ethernet exclusively (verified with network monitor).
- AC-3: If Ethernet disconnects, user is notified that work apps are offline.
- AC-4: User can manually reassign Teams/Outlook to mobile hotspot adapter if needed (temporary policy override).
- AC-5: When Ethernet reconnects, automatic failback to Ethernet (no manual intervention).

### User Story 3: Gamer with Ethernet Priority
**As a** competitive gamer,  
**I want to** ensure my game always uses Ethernet for lowest latency,  
**So that** I never experience lag due to Windows routing game traffic over Wi-Fi.

**Acceptance Criteria**:
- AC-1: User can bind game executable to Ethernet adapter.
- AC-2: Game traffic uses Ethernet even when Wi-Fi has lower metric (force binding).
- AC-3: If Ethernet disconnects mid-game, game's connection drops (expected behavior, fail-closed).
- AC-4: Activity log shows enforcement: "Game.exe: All traffic routed through Ethernet".

### User Story 4: Security Researcher Testing Malware
**As a** security researcher,  
**I want to** block all network access for a suspicious executable,  
**So that** I can safely analyze malware without it communicating with command-and-control servers.

**Acceptance Criteria**:
- AC-1: User can assign "Block All Network" policy to malware.exe.
- AC-2: Malware cannot connect to any external IP address (verified with Wireshark).
- AC-3: Localhost/loopback traffic is still allowed (by default) for debugging tools.
- AC-4: User can optionally block loopback as well (advanced setting).
- AC-5: Activity log records all blocked connection attempts.

### User Story 5: Developer with VPN Split-Tunneling
**As a** software developer,  
**I want to** route my IDE and Git client through Ethernet for fast access to local servers,  
**While** routing my browser through VPN for secure internet browsing,  
**So that** I have optimal performance and security simultaneously.

**Acceptance Criteria**:
- AC-1: User can assign IDE (VS Code) and Git client to Ethernet adapter.
- AC-2: User can assign browser (Chrome) to VPN adapter.
- AC-3: IDE and Git connect to local network (192.168.x.x) via Ethernet (fast, no VPN overhead).
- AC-4: Browser connects to internet via VPN (IP geolocation shows VPN exit node).
- AC-5: If VPN disconnects, browser connections fail (no silent fallback to Ethernet).

---

## 8. Testing and Validation Requirements

### 8.1 Functional Testing

#### Test Case 1: Fail-Closed Enforcement (Critical)
1. Assign application (e.g., Firefox) to Ethernet adapter only.
2. Verify Firefox connects successfully while Ethernet is connected.
3. Unplug Ethernet cable (or disable adapter).
4. Attempt to open website in Firefox ? Expected: Connection fails immediately (timeout or "No internet" error).
5. Verify with packet capture (Wireshark): NO packets from Firefox on Wi-Fi adapter.
6. Reconnect Ethernet.
7. Attempt to open website in Firefox ? Expected: Connection succeeds immediately.

#### Test Case 2: Multi-Process Application (Chrome)
1. Assign Chrome to Wi-Fi adapter.
2. Launch Chrome, open multiple tabs.
3. Verify all Chrome processes (browser, renderer, GPU process) use Wi-Fi.
4. Disable Wi-Fi ? all tabs fail to load (expected).

#### Test Case 3: UWP Application
1. Assign Microsoft Store app to Ethernet.
2. Verify Store can download apps while Ethernet is connected.
3. Disable Ethernet ? Store shows offline error.

#### Test Case 4: DNS Resolution
1. Assign curl.exe to Ethernet (command-line tool for testing).
2. Run `curl https://example.com` while Ethernet connected ? Success.
3. Disable Ethernet ? Run `curl https://example.com` ? Expected: DNS resolution fails or connection fails (no Wi-Fi fallback).

#### Test Case 5: Loopback Exemption
1. Assign application to "Block All Network".
2. Application attempts to connect to 127.0.0.1:8080 (local server) ? Expected: Connection succeeds (loopback exempt).
3. Application attempts to connect to 192.168.1.1 (LAN) ? Expected: Connection fails (blocked).

---

### 8.2 Performance Testing

#### Test Case 6: Throughput Overhead
1. Measure baseline network throughput (iperf3, no policies applied).
2. Apply policy binding iperf3 to test adapter.
3. Measure throughput again ? Expected: < 5% reduction.

#### Test Case 7: Latency Overhead
1. Measure baseline ping latency (ping to gateway, no policies).
2. Apply policy binding ping.exe to test adapter.
3. Measure latency again ? Expected: < 1ms increase.

#### Test Case 8: Scalability
1. Assign 100 unique applications to various adapters (scripted).
2. Launch 50 of them simultaneously.
3. Verify all policies enforced correctly, no crashes.
4. Check service CPU and memory usage ? Expected: < 2% CPU, < 100 MB RAM.

---

### 8.3 Security Testing

#### Test Case 9: Tamper Resistance
1. As standard user (non-admin), attempt to modify policy file ? Expected: Access denied.
2. As standard user, attempt to stop service ? Expected: Access denied.

#### Test Case 10: Service Crash Recovery
1. Forcefully terminate service process (Task Manager, "End Task").
2. Verify service restarts automatically within 10 seconds.
3. Verify policies are re-applied after restart.

---

## 9. Implementation Priorities

### Phase 1 (MVP - Minimum Viable Product)
- Adapter discovery and stable identification (LUID/GUID)
- Executable-based application identification
- Policy modes: Bind to specific adapter, Block all network
- WFP-based enforcement (user-mode filters)
- Basic GUI: Adapter list, application assignment, status indicators
- Policy persistence (JSON file)
- Backend Windows service with auto-start
- Fail-closed enforcement (critical)

### Phase 2 (Enhanced Features)
- Multi-adapter allowed mode (failover within allowed set)
- UWP application support
- DNS resolution per-adapter enforcement
- Activity log and notifications
- Advanced options (terminate on disconnect, loopback control)
- Installer/uninstaller

### Phase 3 (Advanced Features)
- Policy profiles (save/load sets of policies)
- LAN/WAN traffic differentiation
- WFP callout driver for advanced routing
- Support for Windows services (svchost.exe specific service instances)
- Authenticode signature verification for app identity
- Import/export policies

---

## 10. Success Metrics

### Functional Success
- **Zero silent fallbacks**: 100% of test cases confirm fail-closed behavior (no adapter fallback).
- **Policy enforcement accuracy**: 100% of assigned applications use correct adapters (verified with packet capture).

### Performance Success
- Throughput overhead < 5%
- Latency overhead < 1ms
- Service idle CPU < 1%

### Usability Success
- User can assign an application to an adapter in < 30 seconds (timed usability test).
- 90% of beta testers rate UI as "easy to use" or "very easy to use".

### Reliability Success
- Service uptime > 99.9% over 30-day test period.
- Zero policy database corruptions during stress testing (10,000 policy updates).

---

## 11. Open Questions and Risks

### Open Questions
1. **Q**: Should DNS-over-HTTPS (DoH) be detected and treated specially?
   **A**: Phase 2 consideration. For MVP, treat as regular HTTPS traffic.

2. **Q**: How to handle adapter metric changes (user changes metric in Windows settings)?
   **A**: Policies are LUID-based, independent of metrics. Metric only matters for multi-adapter allowed mode (Windows decides routing within allowed set).

3. **Q**: Should the system detect and warn about VPN kill-switch conflicts?
   **A**: Phase 2. For MVP, document that this tool can replace or complement VPN kill-switches.

### Risks
- **Risk 1**: WFP filter conflicts with third-party firewalls.
  - **Mitigation**: Use unique sublayer GUID, test with common firewalls, provide conflict resolution guide.

- **Risk 2**: Performance overhead on low-end hardware.
  - **Mitigation**: Optimize WFP filter rules, minimize per-packet processing, use fast hash tables for policy lookup.

- **Risk 3**: Windows updates breaking WFP API compatibility.
  - **Mitigation**: Pin to stable WFP API versions, monitor Windows Insider builds, maintain compatibility layer.

- **Risk 4**: User accidentally blocks critical system process (Windows Update).
  - **Mitigation**: Protected process list, prominent warnings, fail-safe exclusion list.

---

## 12. Glossary

- **Adapter**: Network interface (Ethernet, Wi-Fi, etc.).
- **LUID (Locally Unique Identifier)**: Windows-assigned stable identifier for network interfaces.
- **GUID (Globally Unique Identifier)**: Persistent identifier for network interfaces.
- **WFP (Windows Filtering Platform)**: Windows kernel framework for packet filtering and network policy enforcement.
- **Fail-Closed**: Security principle where access is denied (blocked) in case of failure or uncertainty.
- **Fail-Open**: Opposite of fail-closed; access is allowed in case of failure (less secure).
- **UWP (Universal Windows Platform)**: Modern Windows app platform (Microsoft Store apps).
- **Split-Tunneling**: VPN feature where only some traffic goes through VPN, rest uses physical adapter.
- **Metered Connection**: Network adapter marked by Windows as having limited data (e.g., mobile hotspot).

---

**END OF SPECIFICATION**
