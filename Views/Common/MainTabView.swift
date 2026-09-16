//
//  MainTabView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//  Revised: removed NavigationSplitView (List(selection:content:) unavailable
//  on iOS); unified to TabView which works on both iPhone and iPad.
//

import SwiftUI

/// Top-level navigation interface using TabView on both iPhone and iPad.
struct MainTabView: View {

    // MARK: - Navigation Tabs

    enum Tab: String, CaseIterable, Identifiable {
        case dashboard   = "Tổng quan"
        case lanScanner  = "Quét LAN"
        case diagnostics = "Chẩn đoán"

        var id: String { rawValue }

        var icon: String {
            switch self {
            case .dashboard:   return "gauge.with.needle.fill"
            case .lanScanner:  return "network"
            case .diagnostics: return "wrench.and.screwdriver.fill"
            }
        }
    }

    // MARK: - State

    @State private var selectedTab: Tab = .dashboard

    // MARK: - Design System Constants

    private let accentColor: Color = .indigo

    // MARK: - Body

    var body: some View {
        TabView(selection: $selectedTab) {
            DashboardView()
                .tabItem {
                    Label(Tab.dashboard.rawValue, systemImage: Tab.dashboard.icon)
                }
                .tag(Tab.dashboard)

            LANScannerView()
                .tabItem {
                    Label(Tab.lanScanner.rawValue, systemImage: Tab.lanScanner.icon)
                }
                .tag(Tab.lanScanner)

            DiagnosticsToolsView()
                .tabItem {
                    Label(Tab.diagnostics.rawValue, systemImage: Tab.diagnostics.icon)
                }
                .tag(Tab.diagnostics)
        }
        .tint(accentColor)
    }
}

#Preview {
    MainTabView()
}
