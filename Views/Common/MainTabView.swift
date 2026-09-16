//
//  MainTabView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Top-level navigation interface adapting between structured Sidebar navigation on iPadOS
/// and classic TabView navigation on iOS.
struct MainTabView: View {
    
    // MARK: - Navigation Tabs
    
    enum Tab: String, CaseIterable, Identifiable {
        case dashboard = "Tổng quan"
        case lanScanner = "Quét LAN"
        case diagnostics = "Chẩn đoán"
        
        var id: String { rawValue }
        
        var icon: String {
            switch self {
            case .dashboard: return "gauge.with.needle.fill"
            case .lanScanner: return "network"
            case .diagnostics: return "wrench.and.screwdriver.fill"
            }
        }
    }
    
    // MARK: - State
    
    @State private var selectedTab: Tab = .dashboard
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    
    var body: some View {
        Group {
            if horizontalSizeClass == .regular {
                // iPad structured sidebar navigation
                NavigationSplitView {
                    List(selection: $selectedTab) {
                        ForEach(Tab.allCases) { tab in
                            NavigationLink(value: tab) {
                                Label(tab.rawValue, systemImage: tab.icon)
                            }
                        }
                    }
                    .navigationTitle("Network Analyzer")
                    .tint(accentColor)
                } detail: {
                    tabContent(for: selectedTab)
                }
            } else {
                // iPhone standard TabView
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
        .preferredColorScheme(.light)
    }
    
    // MARK: - Helper Views
    
    @ViewBuilder
    private func tabContent(for tab: Tab) -> some View {
        switch tab {
        case .dashboard:
            DashboardView()
        case .lanScanner:
            LANScannerView()
        case .diagnostics:
            DiagnosticsToolsView()
        }
    }
}

#Preview {
    MainTabView()
}
