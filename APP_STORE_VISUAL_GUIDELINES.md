# App Store Visual Asset Guidelines & Design Specifications
**Project:** Network Analyzer iOS (`network-analyzer-ios`)  
**Role:** Senior iOS UI/UX Designer  
**Target:** iOS 17 / iOS 18 & iPadOS 17 / iPadOS 18 (App Store Connect Submission)

---

## 1. App Icon Specifications

### Technical Requirements
* **Canvas Size:** **`1024 × 1024 px`** (Square, 1:1 aspect ratio).
* **Color Space:** Display P3 or sRGB.
* **Format:** PNG (24-bit RGB) or JPEG.
* **No Alpha Channel:** Apple strictly rejects icons with transparency (Alpha Channel = No). The image must be completely opaque.
* **No Pre-rounded Corners:** Apple automatically applies its proprietary squircle mask (`Continuous Corner Radius`). Supplying an icon with pre-rendered rounded corners or drop shadows on the canvas edge will result in ugly black borders on device home screens.

---

### 3 Minimalist Concept Proposals (Indigo Accent Dominant)

| Concept | Visual Metaphor | Design Details & Layering |
|---|---|---|
| **Concept 1 (Recommended): Radar Pulse & Node Topology** | Precision & Real-Time Discovery | **Background:** Deep Indigo gradient (`#1E1B4B` to `#312E81`).<br>**Foreground:** Crisp concentric radar arcs in vibrant Indigo/Cyan (`#6366F1` & `#818CF8`) with 3 glowing network node points forming an interconnected triangle. Subtle 1px geometric grid overlay. |
| **Concept 2: Monolithic Hex Shield & Waveform** | Security & Diagnostic Stability | **Background:** Pure Dark Slate / Midnight Indigo (`#0F172A`).<br>**Foreground:** A refined, thin-stroke hexagon outline with an integrated dynamic sine waveform / ping pulse passing through its center. Accented with Electric Indigo neon glow (`#4F46E5`). |
| **Concept 3: Minimalist Network Router Mesh** | Speed, Connectivity & Hardware Native | **Background:** Minimalist Indigo gradient (`#2E1065` to `#3B0764`).<br>**Foreground:** Isometric 3D wireframe representing a central router hub broadcasting clean, geometric signal beams toward responsive peripheral nodes. High-contrast white and Indigo lines. |

---

## 2. App Store Screenshot Requirements

Apple requires screenshots matching specific display viewports. Below are the mandatory and recommended resolutions for iPhone and iPad submissions on App Store Connect:

### Required Display Sizes Table

| Device Class | Display Category | Pixel Dimensions (Portrait) | Status & Notes |
|---|---|---|---|
| **iPhone Primary** | **6.7" / 6.9" Display** (iPhone 16 Pro Max, 15 Pro Max, 14 Pro Max) | **`1290 × 2796 px`** *(or `1320 × 2868 px`)* | **MANDATORY** for modern edge-to-edge iPhones. |
| **iPhone Legacy** | **6.5" Display** (iPhone 11 Pro Max, XS Max, XR) | **`1242 × 2688 px`** | **MANDATORY** (Required for standard 6.5" catalog). |
| **iPhone Home Button** | **5.5" Display** (iPhone 8 Plus, 7 Plus, 6s Plus) | **`1242 × 2208 px`** | **MANDATORY** if your app supports older non-notched screens. |
| **iPad Primary** | **13" / 12.9" Display (6th Gen)** (iPad Pro 12.9" bezelless) | **`2048 × 2732 px`** | **MANDATORY** if supporting iPadOS. |
| **iPad Classic** | **12.9" Display (2nd Gen)** (iPad Pro with Home Button) | **`2048 × 2732 px`** | Recommended to avoid scaling artifacts on legacy iPads. |

---

## 3. High-Converting 5-Screenshot Flow

To maximize App Store conversion rates (CVR), each screenshot must tell a focused feature story with a clear, concise marketing headline (Caption) placed above the device frame:

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        SCREENSHOT FLOW ARCHITECTURE                       │
├───────────────────────────────────────────────────────────────────────────┤
│ [1. DASHBOARD]  [2. LAN SCANNER]  [3. PORT SCAN]  [4. TRACEROUTE] [5. DNS]│
│  "Network        "Instant Subnet   "High-Speed     "Pinpoint Route "Multi-│
│   Overview"       Device Scan"      Port Check"     Hops & RTT"     Record│
└───────────────────────────────────────────────────────────────────────────┘
```

### Screenshot 1: Network Overview (The "Hook")
* **Headline:** *"Real-Time Network Telemetry & Diagnostics"*
* **Sub-headline:** *"Wi-Fi details, cellular technology (5G), and public IP in one glance."*
* **Mockup Content:** `DashboardView` showcasing the active Wi-Fi card (SSID, Subnet Mask, Gateway), Carrier badge ("Viettel / LTE"), and Public IP address.

### Screenshot 2: Subnet LAN Scanner (Core Value)
* **Headline:** *"Discover Every Device On Your Network"*
* **Sub-headline:** *"Fast parallel subnet scan with instant IEEE MAC OUI vendor matching."*
* **Mockup Content:** `LANScannerView` featuring active progress at 100%, sorted IP list displaying Apple, Cisco, Raspberry Pi icons with Online green badges.

### Screenshot 3: TCP Port Scanner (Specialist Power Tool)
* **Headline:** *"High-Speed Non-Blocking TCP Port Sweeper"*
* **Sub-headline:** *"Detect open ports and classify standard IANA network services."*
* **Mockup Content:** `PortScannerView` showing open ports 80 (HTTP), 443 (HTTPS), 22 (SSH), and 445 (SMB) with prominent Indigo service badges.

### Screenshot 4: Hop-by-Hop Traceroute (Technical Precision)
* **Headline:** *"Pinpoint Latency & Route Bottlenecks"*
* **Sub-headline:** *"Real-time ICMP hop visualization with precise RTT measurements."*
* **Mockup Content:** `TracerouteView` displaying 12 intermediate hops to 8.8.8.8 with clean monospaced terminal styling and green RTT indicators (<35ms).

### Screenshot 5: DNS Lookup & RDAP Whois (Domain Intelligence)
* **Headline:** *"Advanced DNS-over-HTTPS & Domain Ownership"*
* **Sub-headline:** *"Query A, AAAA, MX, TXT records or lookup domain registrar details."*
* **Mockup Content:** `WebToolsView` showing resolved `[TXT]` and `[MX]` records with stylish Indigo tags, plus RDAP summary for `apple.com`.

---

## 4. Recommended Tools & Mockup Frameworks

To generate pixel-perfect screenshot assets with real Apple device frames (device bezels, Dynamic Island, and crisp marketing typography):

1. **Dedicated App Store Screenshot Builders:**
   - **AppScreens (appscreens.com):** Generates all required iPhone & iPad resolutions in a single batch, maintaining consistent brand styling.
   - **Rotato (rotato.app):** High-fidelity 3D mockup renderer for macOS, ideal for generating realistic perspective angles and marketing videos.
   - **Picasso / Shots.so (shots.so):** Modern, web-based tool for creating clean device mockups with custom gradient backgrounds.

2. **Automated Xcode UI Test Snapshotting:**
   - **Fastlane `snapshot`:** Fully automated CLI tool that launches your app in simulator viewports, captures localized screens, and frames them automatically via `frameit`.
