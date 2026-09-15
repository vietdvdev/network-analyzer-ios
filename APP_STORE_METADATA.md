# App Store Metadata & Apple Review Package
**Project:** Network Analyzer iOS (`network-analyzer-ios`)  
**Role:** Senior ASO Specialist & iOS Tech Lead

---

## 1. App Store Metadata (ASO Optimized)

### App Name (Max 30 characters)
* **Option 1 (Recommended):** `NetAnalyzer: WiFi & LAN Scanner` *(30 chars)*
* **Option 2:** `Network Analyzer: Ping & Port` *(29 chars)*
* **Option 3:** `NetPulse: Network Diagnostics` *(29 chars)*

---

### Subtitle (Max 30 characters)
* **Option 1 (Recommended):** `WiFi, Ping, Traceroute & Port` *(29 chars)*
* **Option 2:** `LAN Scanner & Network Tools` *(26 chars)*
* **Option 3:** `Fast Network Diagnostics Tool` *(29 chars)*

---

### Keywords (Max 100 characters, comma-separated, no spaces after commas)
```text
wifi,lan,ping,traceroute,port,dns,whois,scanner,network,ip,subnet,router,icmp,oui,rdap,sysadmin,iot,mac
```
*(Exact length: 98 characters — strictly under Apple's 100-character ceiling)*

---

### Promotional Text (Max 170 characters)
> Powerful native network diagnostic suite for iOS. Discover LAN devices, trace packet routes, test latency with ICMP Ping, scan open ports, and resolve DNS records in real time.

---

### App Description (~300 words)

```text
NetAnalyzer is a high-performance, professional-grade network diagnostic and analysis toolkit built natively for iOS and iPadOS. Designed specifically for network administrators, IT specialists, security professionals, and smart home enthusiasts, NetAnalyzer empowers you to inspect, troubleshoot, and optimize your network environment with zero bloat.

KEY FEATURES:

• Subnet LAN Scanner: Rapidly discovers all connected devices, smart home equipment, and hidden hosts across your local IPv4 subnet. Includes instant hardware manufacturer identification via our embedded IEEE MAC OUI database.

• ICMP Ping Utility: Measures Round-Trip Time (RTT) and jitter with unprivileged datagram sockets. Track packet loss and monitor connection reliability in real time.

• Hop-by-Hop Traceroute: Analyzes network routes packet-by-packet. Identifies intermediate router nodes, network bottlenecks, and transit delays using dynamic IP TTL control and ICMP Time-Exceeded capture.

• High-Speed TCP Port Scanner: Non-blocking socket sweeper supporting custom ranges and standard service profiles (HTTP, SSH, SMB, MySQL, RDP). Automatically maps discovered open ports to standard IANA service specifications.

• Advanced DNS & RDAP Whois: Execute DNS-over-HTTPS (DoH) lookups across multi-record types (A, AAAA, MX, TXT, CNAME, NS, CAA). Inspect domain and IP ownership data with modern REST RDAP queries.

• Real-Time Interface Inspector: Track active Wi-Fi properties, cellular carrier technology (5G/LTE), VPN tunnel interfaces, and external Public IP addresses.

ENGINEERED FOR PRIVACY & PERFORMANCE:
Built with Swift 6 and modern SwiftUI, NetAnalyzer delivers a clean, responsive user experience optimized for both Light and Dark modes. Best of all, NetAnalyzer operates 100% locally on your device with no remote analytics, no tracking, and no external data harvesting.
```

---

## 2. Apple App Review Notes (App Review Information)

Provide this exact text in the **App Review Information -> Notes** field in App Store Connect:

```text
Dear Apple Review Team,

This application, NetAnalyzer, is a specialized network diagnostics and troubleshooting utility intended for network engineers, systems administrators, and power users. 

To ensure complete transparency regarding permission prompts, please note why the following permissions are requested:

1. NSLocalNetworkUsageDescription ("Privacy - Local Network Usage Description"):
   - Purpose: The core feature of NetAnalyzer is the "LAN Scanner" and "Port Scanner". To discover active smart home devices and responsive hosts on the user's subnet, the app sends unprivileged TCP probes (e.g., ports 80 and 445) and checks local multicast/Bonjour services via Network.framework. Under iOS 14+, Apple requires explicit local network permission for apps to interact with devices on the local subnet.

2. NSLocationWhenInUseUsageDescription ("Privacy - Location When In Use Usage Description"):
   - Purpose: In compliance with Apple's security policy since iOS 13/14, access to the current Wi-Fi network name (SSID) and Basic Service Set Identifier (BSSID) via CNCopyCurrentNetworkInfo and NetworkExtension is gated behind When-In-Use Location permission. NetAnalyzer utilizes this solely to display the connected Wi-Fi network's SSID and BSSID on the Network Dashboard screen. The app does NOT track, record, or transmit the user's geographical location coordinates.

Note for Testing:
Testing on a physical iOS device connected to an active Wi-Fi network is highly recommended, as the iOS Simulator runs behind a macOS virtual NAT and does not reflect actual local network hardware interfaces or ARP cache responses.

Thank you for your time and assistance in reviewing NetAnalyzer.
```

---

## 3. Privacy Policy (App Store Compliant)

```text
# Privacy Policy for NetAnalyzer

Last Updated: September 14, 2026

NetAnalyzer ("we", "our", or "the app") is committed to protecting your privacy. This Privacy Policy explains our practices regarding data collection and usage.

1. Zero Personal Data Collection
NetAnalyzer is an offline-first network diagnostic tool. We DO NOT collect, store, record, or transmit any personally identifiable information (PII), browsing history, or personal data to external servers or third parties.

2. Local Network & Telemetry Information
All network operations—including IP address calculation, ARP cache inspection, ICMP Ping packets, Traceroute TTL increments, and TCP Port probes—are executed strictly locally on your iOS device. None of your local network topologies, discovered device names, IP addresses, or MAC addresses are ever uploaded or transmitted outside your local environment.

3. External Queries
When you intentionally use features requiring public internet lookups:
- Public IP Resolution: Queries the public ipify API (https://api.ipify.org) to obtain your external IP address.
- DNS Lookup: Queries Cloudflare DNS-over-HTTPS (https://cloudflare-dns.com) to resolve public DNS records.
- RDAP / Whois: Queries the open RDAP registry (https://rdap.org) to fetch domain registration records.
These queries are made directly over secure HTTPS from your device and do not transmit your device identifiers or personal credentials.

4. No Analytics or Third-Party SDKs
NetAnalyzer contains zero third-party advertising SDKs, zero analytics trackers, and zero behavioral tracking mechanisms.

5. Contact Us
If you have any questions or suggestions about our Privacy Policy, please contact us at: support@vietdv.dev
```
