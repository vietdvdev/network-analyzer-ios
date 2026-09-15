# Network Analyzer iOS (`network-analyzer-ios`)

[![Swift](https://img.shields.io/badge/Swift-6.0-orange.svg?style=flat-square&logo=swift)](https://developer.apple.com/swift/)
[![iOS Deployment Target](https://img.shields.io/badge/iOS-17.0%2B%20%7C%2018.0%2B-blue.svg?style=flat-square&logo=apple)](https://developer.apple.com/ios/)
[![Platform](https://img.shields.io/badge/Platform-iOS%20%7C%20iPadOS-lightgrey.svg?style=flat-square)](https://developer.apple.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

High-performance, pure-native network diagnostic and analysis toolkit for iOS and iPadOS. Built from the ground up using **Swift 6 (Structured Concurrency `async`/`await`)**, modern **SwiftUI**, Apple's **`Network.framework`**, and low-level **POSIX C Sockets** for direct networking telemetry.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture & Tech Stack](#-architecture--tech-stack)
- [Project Directory Structure](#-project-directory-structure)
- [Requirements & Getting Started](#-requirements--getting-started)
- [Permissions & Info.plist Configuration](#-permissions--infoplist-configuration)
- [Development Roadmap](#-development-roadmap)
- [Contributing & License](#-contributing--license)

---

## 🔍 Overview

**Network Analyzer iOS** provides systems engineers, network administrators, and security specialists with comprehensive network diagnostic capabilities right on their mobile devices. Unlike standard wrapped apps, this tool interfaces directly with the Darwin kernel and POSIX socket layer to execute raw ICMP, UDP, and non-blocking TCP socket operations alongside Apple's modern network observation frameworks.

---

## 🚀 Key Features

### 1. 🛰️ Parallel LAN Scanner
- **High-throughput Subnet Discovery:** Rapidly scans the entire local `/24` subnet (254 addresses) using parallel Swift structured concurrency (`TaskGroup`) with bounded batching and adaptive timeout windows.
- **Multi-Protocol Hostname Resolution:**
  - **mDNS / Bonjour:** Discovers services and hostnames via `Network.framework`'s `NWBrowser`.
  - **NetBIOS (Port 137):** Sends UDP NetBIOS Name Service queries to identify legacy Windows and Samba devices.
  - **LLMNR (Port 5355):** Link-Local Multicast Name Resolution query support.
  - **Reverse DNS:** In-addr.arpa pointer queries via standard DNS lookup.
  - **SNMP Probe:** Basic discovery querying sysDescr OID `1.3.6.1.2.1.1.1.0`.
- **MAC & Vendor Detection:** Reads system ARP cache tables (`sysctl` / `getifaddrs`) and matches IEEE OUI prefixes against an embedded SQLite/JSON database to display device manufacturer identities.

### 2. 📶 Network Information & Interface Inspector
- **Wi-Fi Diagnostics:** Queries active Wi-Fi properties via `CoreWLAN` / `NetworkExtension` / `CaptiveNetwork` APIs: SSID, BSSID, security protocol, local IPv4/IPv6 address, default Gateway, and Subnet Mask.
- **Cellular & Multi-SIM:** Analyzes carrier data via `CoreTelephony`, network generation indicators (LTE/5G), and interface-specific metrics.
- **External & Public IP:** Fetches public-facing IPv4/IPv6 addresses, primary upstream DNS resolvers, and autonomous system numbers (ASN).
- **Interface Tracking:** Observes real-time interface transitions (Wi-Fi, Cellular, VPN virtual tun/tap, Hotspot) using `NWPathMonitor`.

### 3. 🎯 Ping & Traceroute Tool
- **ICMP Ping:** Utilizes raw ICMP datagram sockets (`IPPROTO_ICMP`) to compute precise Round-Trip Time (RTT), jitter, and packet loss statistics.
- **Hop-by-Hop Traceroute:** 
  - Dynamically increments IP Time-To-Live (TTL) header values (`IP_TTL` sockopt).
  - Captures ICMP *Time Exceeded* (Type 11, Code 0) packets to map intermediate router nodes.
  - Computes per-hop latency (min/avg/max) and maps server coordinates via offline/online GeoIP resolvers.

### 4. ⚡ High-Speed Port Scanner
- **Non-blocking TCP Sockets:** Executes non-blocking TCP connects (`connect()` with `fcntl(O_NONBLOCK)` and `select()` / `kqueue`) for fast port sweeps.
- **Target Profiles:** Supports custom port ranges, common service lists (Top 20 / 100 / 1000), or full range sweeps (`1–65535`).
- **State Classification:** Evaluates socket state flags to classify targets as **Open**, **Closed**, or **Firewalled / Filtered**.
- **Service Mapping:** Automatically associates discovered open ports with standard IANA service specifications.

### 5. 🌐 DNS Lookup & Whois/RDAP Query
- **Direct UDP DNS Engine:** Raw DNS datagram queries crafted over UDP port 53 directly to selected nameservers (System, Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`).
- **Rich Record Types:** Supports parsing for `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `SRV`, `CAA`, and `SVCB` records.
- **Domain & IP Ownership:**
  - Modern REST-based **RDAP (Registration Data Access Protocol)** query parser for ICANN TLDs and RIR IP allocations (ARIN, RIPE, APNIC, etc.).
  - Fallback to traditional RFC 3912 TCP port 43 **Whois** socket client when RDAP endpoints are unavailable.

---

## 🛠️ Architecture & Tech Stack

| Layer / Concern | Technology & Frameworks | Description |
|---|---|---|
| **Language** | Swift 6.0 | Strict concurrency checks (`Sendable`), `async`/`await`, `TaskGroup`, typed throws. |
| **Presentation** | SwiftUI | Reactive declarative UI, modern NavigationStack, full Adaptive Light/Dark appearance. |
| **System Networking** | `Network.framework` | `NWPathMonitor`, `NWBrowser`, `NWConnection` for Bonjour and state monitoring. |
| **Kernel / POSIX Sockets** | Darwin / POSIX C API | `<sys/socket.h>`, `<netinet/ip.h>`, `<netinet/ip_icmp.h>`, `<arpa/inet.h>`, `getifaddrs`, `sysctl`. |
| **Local Data Store** | SQLite / Embedded JSON | Bundled IEEE OUI MAC vendor database and IANA Service-Port tables for offline lookups. |

---

## 📂 Project Directory Structure

```text
network-analyzer-ios/
├── App/
│   ├── NetworkAnalyzerApp.swift           # Main Application entry point (@main)
│   ├── AppConfiguration.swift             # App configuration, flags, and environment injection
│   └── AppDelegate.swift                  # Legacy lifecycle hooks and system notification delegates
│
├── Core/
│   ├── NetworkInfo/
│   │   ├── NetworkInterfaceManager.swift  # getifaddrs wrappers, gateway extraction, IP addressing
│   │   ├── CellularMonitor.swift          # CoreTelephony interface bindings and dual-SIM telemetry
│   │   └── WiFiDetailsProvider.swift      # SSID/BSSID resolution and local network attributes
│   ├── Scanner/
│   │   ├── LANScannerEngine.swift         # Subnet scan coordinator using TaskGroup
│   │   ├── ArpTableReader.swift           # sysctl routing table and ARP cache parser
│   │   └── Protocols/                     # NetBIOS, LLMNR, and SNMP probe implementations
│   ├── Ping/
│   │   ├── ICMPPingClient.swift           # Raw ICMP datagram socket wrapper
│   │   └── PingStatistics.swift           # Latency metrics, jitter calculation, and packet loss
│   ├── Traceroute/
│   │   ├── TracerouteEngine.swift         # TTL increment engine, ICMP Time-Exceeded capture
│   │   └── HopResult.swift                # Per-hop data structure and GeoIP binding
│   ├── PortScan/
│   │   ├── TCPPortScanner.swift           # Non-blocking POSIX socket worker
│   │   └── PortScanProfile.swift          # Presets (Top 100, Full 1-65535, Custom)
│   └── DNS/
│       ├── DNSQueryEngine.swift           # Direct UDP 53 query builder and response parser
│       ├── DNSRecordTypes.swift           # Model definitions for A, AAAA, MX, TXT, SRV, etc.
│       └── RDAPClient.swift               # REST RDAP parser and RFC 3912 Whois socket fallback
│
├── Services/
│   ├── HostnameResolver.swift             # Multicast DNS (NWBrowser), mDNS, and Reverse DNS orchestrator
│   ├── VendorLookupService.swift          # IEEE MAC OUI query provider
│   └── DatabaseService.swift              # SQLite client for port lists and hardware registries
│
├── Views/
│   ├── Dashboard/
│   │   ├── DashboardView.swift            # Top-level status cards (Wi-Fi, Public IP, Cell, Quick Actions)
│   │   └── InterfaceStatusCard.swift      # Active interface detail card
│   ├── LANScanner/
│   │   ├── LANScannerView.swift           # Device list, real-time discovery feeds, and device details
│   │   └── DeviceDetailView.swift         # Selected host details (Open ports, services, vendor)
│   ├── Diagnostics/
│   │   ├── PingView.swift                 # ICMP Ping configuration, real-time chart, and stats
│   │   ├── TracerouteView.swift           # Route hop visualization and ping map
│   │   ├── PortScannerView.swift          # Target selection, port range grid, and log view
│   │   └── DNSLookupView.swift            # Record selector, nameserver config, and RDAP view
│   └── Common/
│       ├── Components/                    # Badges, Gauge dials, Metric cards, Status indicators
│       └── Modifiers/                     # Glassmorphism, card styling, and platform adaptors
│
└── Resources/
    ├── Database/
    │   ├── oui_vendors.sqlite             # Embedded database mapping OUI prefixes to manufacturers
    │   └── iana_ports.json                # Standard port to protocol & service name registry
    └── Assets.xcassets                    # App icons, accent colors, and custom network vector assets
```

---

## 💻 Requirements & Getting Started

### System Requirements
- **macOS:** macOS Sonoma 14.0 or macOS Sequoia 15.0+
- **IDE:** Xcode 16.0 or later
- **Language:** Swift 6.0 toolchain
- **Deployment Target:** iOS 17.0+ / iPadOS 17.0+ (Tested against iOS 18.x)

> [!IMPORTANT]
> **Physical Device Mandatory:** You **MUST** run and test this project on a **Physical iOS Device**.  
> The iOS Simulator runs on a virtualized NAT layer controlled by macOS; it does not have direct access to physical Wi-Fi hardware, lacks accurate local ARP caches, and restricts raw ICMP/broadcast socket behavior.

### Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/vietdvdev/network-analyzer-ios.git
   cd network-analyzer-ios
   ```

2. **Open in Xcode:**
   ```bash
   open NetworkAnalyzer.xcodeproj
   ```

3. **Configure Signing & Capabilities:**
   - Select the target `NetworkAnalyzer` in Xcode.
   - Under **Signing & Capabilities**, select your active **Development Team**.
   - Ensure an appropriate Bundle Identifier is specified.

4. **Run on Device:**
   - Connect your iPhone or iPad via USB/Wi-Fi.
   - Select your physical device as the run destination.
   - Press `Cmd + R` to build and deploy.

---

## 🔒 Permissions & Info.plist Configuration

The application requires specific privacy and network permissions to interact with local hardware interfaces and observe discovery multicasts. Ensure the following keys are properly declared in `Info.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- 1. Permission for discovering devices on the local subnet -->
    <key>NSLocalNetworkUsageDescription</key>
    <string>Network Analyzer requires access to your local network to discover connected devices, measure latency, and perform diagnostic scans.</string>

    <!-- 2. Permission to retrieve Wi-Fi SSID and BSSID information -->
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>Location access is required by iOS to read the current Wi-Fi SSID and BSSID network details.</string>

    <!-- 3. Declared Bonjour services for network service discovery -->
    <key>NSBonjourServices</key>
    <array>
        <string>_http._tcp</string>
        <string>_https._tcp</string>
        <string>_smb._tcp</string>
        <string>_airplay._tcp</string>
        <string>_raop._tcp</string>
        <string>_printer._tcp</string>
        <string>_ipp._tcp</string>
        <string>_googlecast._tcp</string>
        <string>_companion-link._tcp</string>
    </array>
</dict>
</plist>
```

---

## 🗺️ Development Roadmap

The project is structured into six focused development phases:

- [x] **Phase 1: Architecture & Foundation**
  - Project scaffolding with Swift 6 and strict concurrency checking enabled.
  - Setup core network primitives, thread-safe asynchronous wrappers, and baseline SwiftUI navigation.
- [ ] **Phase 2: Local Network Discovery Engine (LAN Scanner)**
  - Implement concurrent `/24` subnet scanning with `TaskGroup`.
  - ARP table cache parser via `sysctl`.
  - Multi-protocol hostname resolution (mDNS/Bonjour, NetBIOS, LLMNR, SNMP).
  - MAC OUI vendor matching against embedded SQLite database.
- [ ] **Phase 3: Network Information & Dashboard**
  - Wi-Fi SSID, BSSID, Gateway, and Subnet Mask extraction.
  - Public IP resolution (IPv4 & IPv6), DNS nameserver detection, and GeoIP/ASN info.
  - Dynamic interface state observer (`NWPathMonitor`).
- [ ] **Phase 4: Diagnostics Suite (Ping, Traceroute & Port Scan)**
  - ICMP Datagram socket implementation with real-time RTT jitter graphs.
  - Hop-by-hop Traceroute engine supporting dynamic TTL adjustment and ICMP Type 11 handling.
  - High-speed non-blocking TCP Port Scanner (`1–65535`) with standard IANA service categorization.
- [ ] **Phase 5: Web & Domain Tools (DNS Engine & Whois/RDAP)**
  - Custom UDP socket DNS resolver supporting major records (`A`, `AAAA`, `MX`, `TXT`, `CNAME`, `SRV`, `CAA`, `SVCB`).
  - REST RDAP client with RFC 3912 TCP 43 Whois protocol fallback.
- [ ] **Phase 6: Performance Optimization, Hardening & Release**
  - Memory profiling and socket descriptor leak audit.
  - Adaptive battery and network throttling for long-running diagnostic sessions.
  - TestFlight beta distribution and App Store release preparation.

---

## 📄 Contributing & License

Contributions are welcome! Please open an issue or submit a pull request for improvements, bug fixes, or new protocol probe support.

Distributed under the **MIT License**. See `LICENSE` for more information.
