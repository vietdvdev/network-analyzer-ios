//
//  DashboardView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Dashboard screen presenting an overview of active connection interfaces,
/// local subnet addressing, cellular provider metrics, and public internet telemetry.
struct DashboardView: View {
    
    // MARK: - State & Dependencies
    
    @State private var networkProvider = NetworkDetailsProvider.shared
    @State private var localWiFiInfo: NetworkInterfaceInfo?
    @State private var isLoadingPublicIP: Bool = false
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let cardCornerRadius: CGFloat = 8
    
    // MARK: - Body
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // 1. Current Active Connection Card
                    activeConnectionCard
                    
                    // 2. Local Subnet & Interface Parameters Card
                    localParametersCard
                    
                    // 3. Cellular & Carrier Card
                    cellularCard
                    
                    // 4. Internet & Public Addressing Card
                    internetCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 16)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Thông tin Mạng")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    refreshButton
                }
            }
            .task {
                await refreshData()
            }
        }
        .preferredColorScheme(.light) // Crisp Light Mode experience
    }
    
    // MARK: - Subviews & Cards
    
    /// Card displaying active connection type and real-time status.
    private var activeConnectionCard: some View {
        dashboardCard(title: "Kết nối hiện tại", icon: activeInterfaceIcon) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Trạng thái kết nối")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        
                        Text(networkProvider.currentStatus.activeInterface)
                            .font(.title3)
                            .fontWeight(.bold)
                            .foregroundStyle(Color(uiColor: .label))
                    }
                    
                    Spacer()
                    
                    // Status Badge
                    HStack(spacing: 6) {
                        Circle()
                            .fill(networkProvider.currentStatus.activeInterface != "No Connection" ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        
                        Text(networkProvider.currentStatus.activeInterface != "No Connection" ? "Đang kết nối" : "Mất kết nối")
                            .font(.caption)
                            .fontWeight(.medium)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color(uiColor: .tertiarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: cardCornerRadius, style: .continuous))
                }
            }
        }
    }
    
    /// Card presenting local LAN addressing (IP, Subnet Mask, Host capacity).
    private var localParametersCard: some View {
        dashboardCard(title: "Thông số cục bộ", icon: "wifi") {
            VStack(spacing: 12) {
                if let wifi = localWiFiInfo {
                    dataRow(title: "Địa chỉ IPv4 LAN", value: wifi.ipAddress, isMonospaced: true)
                    Divider()
                    dataRow(title: "Subnet Mask", value: wifi.netmask, isMonospaced: true)
                    Divider()
                    dataRow(title: "Khả dụng trong Subnet", value: "\(wifi.subnetRange.count) địa chỉ host", isMonospaced: false)
                } else {
                    HStack {
                        Text("Không có kết nối Wi-Fi khả dụng")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }
    
    /// Card presenting SIM carrier and radio access technology (LTE / 5G).
    private var cellularCard: some View {
        dashboardCard(title: "Mạng di động", icon: "antenna.radiowaves.left.and.right") {
            VStack(spacing: 12) {
                dataRow(
                    title: "Nhà mạng",
                    value: networkProvider.currentStatus.carrierName ?? "Không xác định",
                    isMonospaced: false
                )
                Divider()
                dataRow(
                    title: "Chuẩn sóng di động",
                    value: networkProvider.currentStatus.radioAccessTechnology ?? "Không có tín hiệu",
                    isMonospaced: false
                )
            }
        }
    }
    
    /// Card displaying public-facing IP details with on-demand refresh indicator.
    private var internetCard: some View {
        dashboardCard(title: "Internet", icon: "globe") {
            VStack(spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Địa chỉ Public IP")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        
                        if isLoadingPublicIP {
                            HStack(spacing: 6) {
                                ProgressView()
                                    .controlSize(.small)
                                    .tint(accentColor)
                                Text("Đang truy vấn...")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                        } else {
                            Text(networkProvider.currentStatus.publicIP ?? "Không xác định")
                                .font(.headline)
                                .fontWeight(.bold)
                                .foregroundStyle(Color(uiColor: .label))
                                .monospacedDigit()
                        }
                    }
                    
                    Spacer()
                }
            }
        }
    }
    
    // MARK: - Reusable Card Components
    
    /// Generic card container adhering to the design system with minimal corner radius.
    private func dashboardCard<Content: View>(
        title: String,
        icon: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            // Card Header
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(accentColor)
                
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color(uiColor: .label))
                
                Spacer()
            }
            
            // Content
            content()
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: cardCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: cardCornerRadius, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
        )
    }
    
    /// Single row displaying parameter title in secondary caption and value in bold headline.
    private func dataRow(title: String, value: String, isMonospaced: Bool) -> some View {
        HStack {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            
            Spacer()
            
            Text(value)
                .font(.subheadline)
                .fontWeight(.bold)
                .foregroundStyle(Color(uiColor: .label))
                .modify { view in
                    if isMonospaced {
                        view.monospacedDigit()
                    } else {
                        view
                    }
                }
        }
    }
    
    /// Toolbar refresh button.
    private var refreshButton: some View {
        Button {
            Task {
                await refreshData()
            }
        } label: {
            Image(systemName: "arrow.clockwise")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(accentColor)
        }
    }
    
    // MARK: - Dynamic Properties & Actions
    
    /// Determines the SF Symbol representing the current active interface.
    private var activeInterfaceIcon: String {
        switch networkProvider.currentStatus.activeInterface {
        case "Wi-Fi":
            return "wifi"
        case "Cellular":
            return "antenna.radiowaves.left.and.right"
        case "VPN":
            return "lock.shield"
        case "Wired":
            return "cable.connector"
        default:
            return "network.slash"
        }
    }
    
    /// Asynchronously reloads interface details, Wi-Fi info, and public IP.
    private func refreshData() async {
        // Read local POSIX Wi-Fi data
        localWiFiInfo = NetworkHelper.shared.getLocalWiFiDetails()
        
        // Refresh cellular & external IP
        isLoadingPublicIP = true
        await networkProvider.refreshAllDetails()
        isLoadingPublicIP = false
    }
}

// MARK: - View Extension Helper

private extension View {
    @ViewBuilder
    func modify<Content: View>(@ViewBuilder transform: (Self) -> Content) -> Content {
        transform(self)
    }
}

#Preview {
    DashboardView()
}
