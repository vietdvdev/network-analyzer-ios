//
//  DiagnosticsToolsView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Main Hub presenting diagnostic network tools such as ICMP Ping, Traceroute, TCP Port Scanner, and Web/DNS Tools.
struct DiagnosticsToolsView: View {
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        PingView()
                    } label: {
                        toolRow(
                            title: "ICMP Ping",
                            subtitle: "Đo độ trễ RTT và kiểm tra mất gói tin",
                            icon: "network"
                        )
                    }
                    
                    NavigationLink {
                        TracerouteView()
                    } label: {
                        toolRow(
                            title: "Traceroute",
                            subtitle: "Dò tìm đường đi và các router trung gian theo hop",
                            icon: "point.topleft.down.to.point.bottomright.curvepath"
                        )
                    }
                    
                    NavigationLink {
                        PortScannerView()
                    } label: {
                        toolRow(
                            title: "Port Scanner",
                            subtitle: "Quét các cổng TCP mở và dịch vụ hoạt động",
                            icon: "door.left.hand.open"
                        )
                    }
                    
                    NavigationLink {
                        WebToolsView()
                    } label: {
                        toolRow(
                            title: "DNS & Whois / RDAP",
                            subtitle: "Tra cứu đa bản ghi DNS và thông tin chủ sở hữu",
                            icon: "globe.asia.australia.fill"
                        )
                    }
                } header: {
                    Text("Bộ công cụ chẩn đoán")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .textCase(.uppercase)
                        .foregroundStyle(.secondary)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Chẩn đoán mạng")
            .navigationBarTitleDisplayMode(.inline)
        }
        .preferredColorScheme(.light)
    }
    
    // MARK: - Subviews
    
    private func toolRow(title: String, subtitle: String, icon: String) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                    .fill(accentColor.opacity(0.12))
                    .frame(width: 38, height: 38)
                
                Image(systemName: icon)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(accentColor)
            }
            
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.headline)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color(uiColor: .label))
                
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(Color(uiColor: .secondaryLabel))
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    DiagnosticsToolsView()
}
