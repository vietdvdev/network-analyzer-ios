//
//  DeviceDetailView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-15.
//

import SwiftUI

/// Detailed information screen for a discovered LAN device,
/// showing addressing, vendor identity, and quick-action port scanning.
struct DeviceDetailView: View {
    
    // MARK: - Properties
    
    let device: DiscoveredDevice
    
    @State private var quickScanResults: [PortResult] = []
    @State private var isScanning: Bool = false
    @State private var resolvedHostname: String?
    
    // MARK: - Design System
    
    private let accentColor: Color = .indigo
    
    // MARK: - Quick Scan Ports
    
    private let quickScanPorts = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    private var openPorts: [PortResult] {
        quickScanResults.filter { $0.state == .open }
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Device Identity Card
                identityCard
                
                // Addressing Card
                addressingCard
                
                // Quick Port Scan Card
                portScanCard
                
                // Quick Actions
                actionsCard
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle(device.ipAddress)
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
        .task {
            await resolveHostname()
        }
    }
    
    // MARK: - Subviews
    
    private var identityCard: some View {
        VStack(spacing: 14) {
            IconBadge(icon: deviceIcon, size: 56)
            
            Text(device.ipAddress)
                .font(.title2)
                .fontWeight(.bold)
                .monospacedDigit()
            
            if let hostname = resolvedHostname ?? device.hostname {
                Text(hostname)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            
            StatusBadge(
                label: device.isAlive ? "Online" : "Offline",
                color: device.isAlive ? .green : .gray
            )
        }
        .frame(maxWidth: .infinity)
        .cardStyle()
    }
    
    private var addressingCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "network")
                    .foregroundStyle(accentColor)
                Text("Thông tin địa chỉ")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Spacer()
            }
            
            InfoRow(title: "Địa chỉ IPv4", value: device.ipAddress, isMonospaced: true)
            Divider()
            InfoRow(title: "Địa chỉ MAC", value: device.macAddress ?? "Chưa xác định", isMonospaced: true)
            Divider()
            InfoRow(title: "Nhà sản xuất", value: device.vendorName ?? "Không rõ")
            
            if let hostname = resolvedHostname ?? device.hostname {
                Divider()
                InfoRow(title: "Hostname", value: hostname)
            }
        }
        .cardStyle()
    }
    
    private var portScanCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "door.left.hand.open")
                    .foregroundStyle(accentColor)
                Text("Cổng dịch vụ")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                
                Spacer()
                
                if !quickScanResults.isEmpty {
                    Text("\(openPorts.count) cổng mở")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundStyle(openPorts.isEmpty ? .secondary : accentColor)
                        .monospacedDigit()
                }
            }
            
            if isScanning {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                        .tint(accentColor)
                    Text("Đang quét 15 cổng thông dụng...")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 8)
            } else if quickScanResults.isEmpty {
                Button {
                    runQuickScan()
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "bolt.fill")
                            .font(.caption)
                        Text("Quét nhanh cổng dịch vụ")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .foregroundStyle(.white)
                    .background(accentColor)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
                .buttonStyle(.plain)
            } else if openPorts.isEmpty {
                Text("Không phát hiện cổng nào mở trên thiết bị này.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                VStack(spacing: 8) {
                    ForEach(openPorts) { result in
                        HStack {
                            HStack(spacing: 8) {
                                IconBadge(icon: "lock.open.fill", size: 30)
                                
                                VStack(alignment: .leading, spacing: 1) {
                                    Text("Port \(result.port)")
                                        .font(.subheadline)
                                        .fontWeight(.bold)
                                        .monospacedDigit()
                                    
                                    Text(DatabaseService.shared.getServiceName(port: result.port) ?? "Unknown")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            
                            Spacer()
                            
                            StatusBadge(label: "Open", color: .green)
                        }
                        
                        if result.id != openPorts.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
        .cardStyle()
    }
    
    private var actionsCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "bolt.horizontal.fill")
                    .foregroundStyle(accentColor)
                Text("Thao tác nhanh")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Spacer()
            }
            
            NavigationLink {
                PingView(prefillHost: device.ipAddress)
            } label: {
                HStack(spacing: 12) {
                    IconBadge(icon: "network", size: 32)
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Ping thiết bị này")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundStyle(Color(uiColor: .label))
                        Text("Kiểm tra độ trễ RTT và mất gói tin")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    
                    Spacer()
                    
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)
        }
        .cardStyle()
    }
    
    // MARK: - Computed Properties
    
    private var deviceIcon: String {
        let vendor = (device.vendorName ?? "").lowercased()
        if vendor.contains("apple") {
            return "laptopcomputer.and.iphone"
        } else if vendor.contains("cisco") || vendor.contains("tp-link") || vendor.contains("router") {
            return "wifi.router.fill"
        } else if vendor.contains("raspberry") {
            return "memorychip.fill"
        } else if vendor.contains("vmware") || vendor.contains("server") {
            return "server.rack"
        } else {
            return "desktopcomputer"
        }
    }
    
    // MARK: - Actions
    
    private func resolveHostname() async {
        guard device.hostname == nil else {
            resolvedHostname = device.hostname
            return
        }
        resolvedHostname = await HostnameResolver.shared.resolve(ip: device.ipAddress)
    }
    
    private func runQuickScan() {
        isScanning = true
        Task {
            let results = await PortScannerEngine.shared.scanPorts(ip: device.ipAddress, ports: quickScanPorts)
            await MainActor.run {
                self.quickScanResults = results
                self.isScanning = false
            }
        }
    }
}

#Preview {
    NavigationStack {
        DeviceDetailView(device: DiscoveredDevice(
            ipAddress: "192.168.1.10",
            hostname: "MacBook-Pro.local",
            macAddress: "3C:22:FB:12:34:56",
            vendorName: "Apple, Inc."
        ))
    }
}
