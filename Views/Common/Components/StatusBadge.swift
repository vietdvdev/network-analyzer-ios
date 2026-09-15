//
//  StatusBadge.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-15.
//

import SwiftUI

/// Reusable status indicator badge with colored dot and label text.
struct StatusBadge: View {
    let label: String
    let color: Color
    
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            
            Text(label)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundStyle(color)
        }
    }
}

/// Reusable icon badge with Indigo-tinted background square.
struct IconBadge: View {
    let icon: String
    let size: CGFloat
    let accentColor: Color
    
    init(icon: String, size: CGFloat = 38, accentColor: Color = .indigo) {
        self.icon = icon
        self.size = size
        self.accentColor = accentColor
    }
    
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(accentColor.opacity(0.12))
                .frame(width: size, height: size)
            
            Image(systemName: icon)
                .font(.system(size: size * 0.45, weight: .semibold))
                .foregroundStyle(accentColor)
        }
    }
}

#Preview {
    VStack(spacing: 20) {
        StatusBadge(label: "Online", color: .green)
        StatusBadge(label: "Closed", color: .red)
        IconBadge(icon: "wifi")
        IconBadge(icon: "desktopcomputer")
    }
    .padding()
}
