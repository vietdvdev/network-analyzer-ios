//
//  NetworkDetailsProvider.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Network
import CoreTelephony
import SystemConfiguration
import Observation

/// Model encapsulating current physical and virtual interface states.
public struct NetworkStatusInfo: Sendable, Equatable {
    /// Active interface designation: "Wi-Fi", "Cellular", "Wired", "VPN", or "No Connection".
    public var activeInterface: String
    
    /// Carrier name of the active SIM/eSIM slot.
    public var carrierName: String?
    
    /// Current cellular radio technology: "5G", "LTE", "3G", "2G", etc.
    public var radioAccessTechnology: String?
    
    /// Public external IPv4/IPv6 address obtained via remote resolver.
    public var publicIP: String?
    
    public init(
        activeInterface: String = "Unknown",
        carrierName: String? = nil,
        radioAccessTechnology: String? = nil,
        publicIP: String? = nil
    ) {
        self.activeInterface = activeInterface
        self.carrierName = carrierName
        self.radioAccessTechnology = radioAccessTechnology
        self.publicIP = publicIP
    }
}

/// Observable provider monitoring real-time network transitions, cellular carrier metadata, and public IP resolution.
@Observable
public final class NetworkDetailsProvider: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = NetworkDetailsProvider()
    
    // MARK: - Observable State
    
    public var currentStatus: NetworkStatusInfo = NetworkStatusInfo()
    
    // MARK: - Private Members
    
    private let pathMonitor: NWPathMonitor
    private let monitorQueue = DispatchQueue(label: "com.networkanalyzer.pathmonitor", qos: .utility)
    private let telephonyInfo = CTTelephonyNetworkInfo()
    
    private init() {
        self.pathMonitor = NWPathMonitor()
        startMonitoring()
        refreshCellularDetails()
    }
    
    deinit {
        pathMonitor.cancel()
    }
    
    // MARK: - Public APIs
    
    /// Refreshes all network details asynchronously, including public IP resolution.
    public func refreshAllDetails() async {
        refreshCellularDetails()
        let ip = await fetchPublicIP()
        
        await MainActor.run {
            self.currentStatus.publicIP = ip
        }
    }
    
    /// Fetches the external public IP address from ipify with a strict timeout configuration.
    ///
    /// - Returns: IPv4/IPv6 string if resolved, or "Unknown" / fallback message.
    public func fetchPublicIP() async -> String? {
        guard let url = URL(string: "https://api.ipify.org") else {
            return nil
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 4.0 // Fast timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode),
                  let ipString = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !ipString.isEmpty else {
                return nil
            }
            return ipString
        } catch {
            return nil
        }
    }
    
    /// Queries `CTTelephonyNetworkInfo` to inspect carrier names and active radio technology.
    public func fetchCellularInfo() -> (carrierName: String?, radioTech: String?) {
        var carrier: String?
        var radioTech: String?
        
        // 1. Carrier Resolution
        if let providers = telephonyInfo.serviceSubscriberCellularProviders {
            for (_, provider) in providers {
                if let name = provider.carrierName, !name.isEmpty {
                    carrier = name
                    break
                }
            }
        }
        
        // 2. Radio Access Technology Resolution
        if let radioDict = telephonyInfo.serviceCurrentRadioAccessTechnology {
            for (_, rawTech) in radioDict {
                radioTech = mapRadioAccessTechnology(rawTech)
                if radioTech != nil { break }
            }
        }
        
        return (carrier, radioTech)
    }
    
    // MARK: - Interface Monitoring (NWPathMonitor)
    
    /// Starts observing interface status and updates `currentStatus.activeInterface`.
    public func startMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            
            let interfaceType = self.resolveActiveInterface(from: path)
            let cellInfo = self.fetchCellularInfo()
            
            Task { @MainActor in
                self.currentStatus.activeInterface = interfaceType
                self.currentStatus.carrierName = cellInfo.carrierName
                self.currentStatus.radioAccessTechnology = cellInfo.radioTech
            }
        }
        
        pathMonitor.start(queue: monitorQueue)
    }
    
    // MARK: - Private Helpers
    
    private func refreshCellularDetails() {
        let info = fetchCellularInfo()
        Task { @MainActor in
            self.currentStatus.carrierName = info.carrierName
            self.currentStatus.radioAccessTechnology = info.radioTech
        }
    }
    
    /// Resolves the primary active connection type and flags virtual VPN tunnels.
    private func resolveActiveInterface(from path: NWPath) -> String {
        guard path.status == .satisfied else {
            return "No Connection"
        }
        
        // Check for active VPN or virtual tunnel flags
        let isVPN = path.isScoped || path.availableInterfaces.contains(where: {
            $0.name.hasPrefix("utun") || $0.name.hasPrefix("ppp") || $0.name.hasPrefix("ipsec")
        })
        
        if isVPN {
            return "VPN"
        }
        
        if path.usesInterfaceType(.wifi) {
            return "Wi-Fi"
        } else if path.usesInterfaceType(.cellular) {
            return "Cellular"
        } else if path.usesInterfaceType(.wiredEthernet) {
            return "Wired"
        } else {
            return "Other"
        }
    }
    
    /// Converts `CTRadioAccessTechnology` constants into user-friendly strings.
    private func mapRadioAccessTechnology(_ raw: String) -> String {
        switch raw {
        case CTRadioAccessTechnologyNR, CTRadioAccessTechnologyNRNSA:
            return "5G"
        case CTRadioAccessTechnologyLTE:
            return "LTE"
        case CTRadioAccessTechnologyeHRPD,
             CTRadioAccessTechnologyHSDPA,
             CTRadioAccessTechnologyHSUPA,
             CTRadioAccessTechnologyWCDMA,
             CTRadioAccessTechnologyCDMAEVDORev0,
             CTRadioAccessTechnologyCDMAEVDORevA,
             CTRadioAccessTechnologyCDMAEVDORevB:
            return "3G"
        case CTRadioAccessTechnologyGPRS,
             CTRadioAccessTechnologyEdge,
             CTRadioAccessTechnologyCDMA1x:
            return "2G"
        default:
            return "Cellular"
        }
    }
}
