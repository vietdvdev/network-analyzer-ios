//
//  NetworkAnalyzerApp.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import SwiftUI

/// Main application entry point for Network Analyzer.
/// Initializes core services and presents the root navigation interface.
@main
struct NetworkAnalyzerApp: App {
    
    // MARK: - Pre-warm Services
    
    /// Force-load DatabaseService at launch so OUI and port dictionaries
    /// are parsed from JSON once and cached in memory for O(1) lookups.
    private let databaseService = DatabaseService.shared
    
    /// Start NWPathMonitor observation at launch to immediately reflect
    /// active interface state (Wi-Fi, Cellular, VPN) on the Dashboard.
    private let networkProvider = NetworkDetailsProvider.shared
    
    // MARK: - Scene
    
    var body: some Scene {
        WindowGroup {
            MainTabView()
                .tint(.indigo) // Global accent color propagation
        }
    }
}
