//
//  LANScannerView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Screen displaying the active local network scan, real-time progress, and discovered hosts
/// with offline IEEE OUI vendor identification and device categorization.
struct LANScannerView: View {
    
    // MARK: - State & ViewModel
    
    @State private var viewModel = LANScannerViewModel()
    @State private var searchFilter: String = ""
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    
    // MARK: - Filtered Devices
    
    private var filteredDevices: [DiscoveredDevice] {
        let filter = searchFilter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !filter.isEmpty else { return viewModel.devices }
        
        return viewModel.devices.filter { device in
            let ipMatch = device.ipAddress.contains(filter)
            let hostMatch = device.hostname?.lowercased().contains(filter) ?? false
            let vendorMatch = (device.vendorName ?? vendorFor(device: device)).lowercased().contains(filter)
            return ipMatch || hostMatch || vendorMatch
        }
    }
    
    // MARK: - Body
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Scanning Progress Banner
                if viewModel.isScanning {
                    scanProgressHeader
                }
                
                // Main Content
                Group {
                    if viewModel.devices.isEmpty && !viewModel.isScanning {
                        emptyStateView
                    } else {
                        deviceListView
                    }
                }
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("LAN Scanner")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $searchFilter, prompt: "Lọc theo IP, Hostname hoặc Hãng sản xuất")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    scanActionButton
                }
            }
        }
        .preferredColorScheme(.light) // Optimized for crisp Light Mode
    }
    
    // MARK: - Subviews
    
    /// Top scanning status indicator with linear progress and percentage.
    private var scanProgressHeader: some View {
        VStack(spacing: 8) {
            HStack {
                HStack(spacing: 6) {
                    ProgressView()
                        .controlSize(.small)
                        .tint(accentColor)
                    
                    Text("Đang quét dải Subnet...")
                        .font(.subheadline)
                        .fontWeight(.medium)
                        .foregroundStyle(accentColor)
                }
                
                Spacer()
                
                Text("\(Int(viewModel.progress * 100))%")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            
            ProgressView(value: viewModel.progress, total: 1.0)
                .progressViewStyle(.linear)
                .tint(accentColor)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .overlay(alignment: .bottom) {
            Divider()
        }
    }
    
    /// Main List displaying discovered hosts.
    private var deviceListView: some View {
        List {
            Section {
                ForEach(filteredDevices) { device in
                    deviceRow(device)
                        .listRowInsets(EdgeInsets(top: 8, leading: 14, bottom: 8, trailing: 14))
                }
            } header: {
                HStack {
                    Text("Thiết bị phát hiện")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .textCase(.uppercase)
                        .foregroundStyle(.secondary)
                    
                    Spacer()
                    
                    Text("\(filteredDevices.count) thiết bị")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
        }
        .listStyle(.insetGrouped)
    }
    
    /// Individual row component for a discovered device.
    private func deviceRow(_ device: DiscoveredDevice) -> some View {
        let vendor = vendorFor(device: device)
        let iconName = deviceIcon(for: vendor)
        
        return HStack(spacing: 12) {
            // Minimalist icon badge with Indigo accent
            ZStack {
                RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                    .fill(accentColor.opacity(0.12))
                    .frame(width: 40, height: 40)
                
                Image(systemName: iconName)
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(accentColor)
            }
            
            // Device Address & Vendor Details
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(device.ipAddress)
                        .font(.headline)
                        .fontWeight(.semibold)
                        .foregroundStyle(Color(uiColor: .label))
                        .monospacedDigit()
                    
                    if let host = device.hostname, !host.isEmpty {
                        Text("(\(host))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                
                // Vendor identity from DatabaseService
                HStack(spacing: 4) {
                    Image(systemName: "cpu")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    
                    Text(vendor)
                        .font(.subheadline)
                        .foregroundStyle(Color(uiColor: .secondaryLabel))
                        .lineLimit(1)
                }
            }
            
            Spacer()
            
            // Alive status indicator circle
            HStack(spacing: 6) {
                Circle()
                    .fill(device.isAlive ? Color.green : Color.gray)
                    .frame(width: 8, height: 8)
                
                Text(device.isAlive ? "Online" : "Offline")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundStyle(device.isAlive ? Color.green : Color.secondary)
            }
        }
        .padding(.vertical, 4)
    }
    
    /// Empty State placeholder displayed before initial scan.
    private var emptyStateView: some View {
        ContentUnavailableView {
            Label {
                Text("Chưa phát hiện thiết bị")
                    .font(.title3)
                    .fontWeight(.semibold)
            } icon: {
                Image(systemName: "network")
                    .font(.system(size: 48))
                    .foregroundStyle(accentColor)
            }
        } description: {
            Text("Nhấn bắt đầu quét để dò tìm toàn bộ dải IP mạng nội bộ và phân giải hãng sản xuất thiết bị.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        } actions: {
            Button {
                triggerScan()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "play.fill")
                        .font(.caption)
                    Text("Bắt đầu quét mạng")
                        .fontWeight(.semibold)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
                .background(accentColor)
                .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            }
            .buttonStyle(.plain)
        }
    }
    
    /// Navigation toolbar action button.
    private var scanActionButton: some View {
        Button {
            if viewModel.isScanning {
                viewModel.stopScan()
            } else {
                triggerScan()
            }
        } label: {
            if viewModel.isScanning {
                Text("Dừng")
                    .fontWeight(.semibold)
                    .foregroundStyle(.red)
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.clockwise")
                        .font(.footnote.weight(.semibold))
                    Text("Quét")
                        .fontWeight(.semibold)
                }
                .foregroundStyle(accentColor)
            }
        }
    }
    
    // MARK: - Vendor & Icon Resolution
    
    /// Resolves vendor name using DatabaseService offline dictionary.
    private func vendorFor(device: DiscoveredDevice) -> String {
        if let explicit = device.vendorName, !explicit.isEmpty {
            return explicit
        }
        if let mac = device.macAddress, let resolved = DatabaseService.shared.getVendorName(macPrefix: mac) {
            return resolved
        }
        // Fallback vendor assignment for common gateway / test nodes
        if device.ipAddress.hasSuffix(".1") {
            return "Router / Gateway Network Device"
        }
        return "Thiết bị không rõ (Generic Host)"
    }
    
    /// Determines an appropriate SF Symbol based on the hardware vendor.
    private func deviceIcon(for vendor: String) -> String {
        let v = vendor.lowercased()
        if v.contains("apple") {
            return "laptopcomputer.and.iphone"
        } else if v.contains("cisco") || v.contains("router") || v.contains("tp-link") {
            return "wifi.router.fill"
        } else if v.contains("raspberry") {
            return "memorychip.fill"
        } else if v.contains("vmware") || v.contains("server") {
            return "server.rack"
        } else if v.contains("google") || v.contains("xiaomi") {
            return "smartphone"
        } else {
            return "desktopcomputer"
        }
    }
    
    // MARK: - Actions
    
    private func triggerScan() {
        Task {
            viewModel.startScan()
        }
    }
}

#Preview {
    LANScannerView()
}
