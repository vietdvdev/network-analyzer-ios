//
//  CardStyle.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-15.
//

import SwiftUI

/// Design system `ViewModifier` providing the standard card container appearance
/// used throughout the application: opaque background, minimal border radius, and subtle separator stroke.
struct CardStyle: ViewModifier {
    
    var cornerRadius: CGFloat = 8
    
    func body(content: Content) -> some View {
        content
            .padding(16)
            .background(Color(uiColor: .secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
            )
    }
}

extension View {
    /// Applies the standard card container styling from the design system.
    func cardStyle(cornerRadius: CGFloat = 8) -> some View {
        modifier(CardStyle(cornerRadius: cornerRadius))
    }
}
