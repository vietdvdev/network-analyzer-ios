//
//  InfoRow.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-15.
//

import SwiftUI

/// Reusable row component displaying a label–value pair for network parameter display.
struct InfoRow: View {
    let title: String
    let value: String
    var isMonospaced: Bool = false
    
    var body: some View {
        HStack {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            
            Spacer()
            
            Text(value)
                .font(.subheadline)
                .fontWeight(.bold)
                .foregroundStyle(Color(uiColor: .label))
                .monospacedDigit(isMonospaced)
        }
    }
}

// MARK: - Helper Extension

private extension View {
    @ViewBuilder
    func monospacedDigit(_ enabled: Bool) -> some View {
        if enabled {
            self.monospacedDigit()
        } else {
            self
        }
    }
}

#Preview {
    VStack(spacing: 12) {
        InfoRow(title: "Địa chỉ IPv4 LAN", value: "192.168.1.15", isMonospaced: true)
        Divider()
        InfoRow(title: "Subnet Mask", value: "255.255.255.0", isMonospaced: true)
        Divider()
        InfoRow(title: "Nhà mạng", value: "Viettel")
    }
    .padding()
}
