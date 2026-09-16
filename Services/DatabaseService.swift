//
//  DatabaseService.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation

/// Fast offline database provider for IANA port service names and IEEE MAC OUI vendors.
public final class DatabaseService: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = DatabaseService()
    
    // MARK: - Internal Lookup Dictionaries (O(1) Access)
    
    /// Maps Port number to standard Service name (e.g., `80: "HTTP"`).
    private var portDictionary: [Int: String] = [:]
    
    /// Maps normalized MAC OUI prefix (e.g., `"00:1A:2B"`) to Manufacturer name.
    private var vendorDictionary: [String: String] = [:]
    
    // MARK: - Initialization & Parsing
    
    public init() {
        loadPortsDatabase()
        loadVendorDatabase()
    }
    
    // MARK: - Public Lookup APIs
    
    /// Returns the standard IANA service name for a given port number with O(1) complexity.
    ///
    /// - Parameter port: TCP/UDP port integer (e.g. 80, 443, 22).
    /// - Returns: Standard service string (e.g., "HTTP", "HTTPS", "SSH"), or `nil` if unregistered.
    public func getServiceName(port: Int) -> String? {
        return portDictionary[port]
    }
    
    /// Returns the hardware manufacturer name matching the MAC address prefix (first 3 octets).
    ///
    /// Accepts varied formats such as `"00:1A:2B"`, `"00-1A-2B"`, or `"001A2B"`, normalizing them
    /// automatically before querying.
    ///
    /// - Parameter macPrefix: MAC OUI string (e.g., `"00:1A:2B"` or `"00:1a:2b:3c:4d:5e"`).
    /// - Returns: Manufacturer name (e.g., "Cisco Systems, Inc"), or `nil` if not found.
    public func getVendorName(macPrefix: String) -> String? {
        guard let normalizedPrefix = normalizeOUIPrefix(macPrefix) else {
            return nil
        }
        return vendorDictionary[normalizedPrefix]
    }
    
    // MARK: - Data Loaders
    
    private func loadPortsDatabase() {
        guard let url = Bundle.main.url(forResource: "ports", withExtension: "json") ??
                Bundle(for: Self.self).url(forResource: "ports", withExtension: "json") else {
            return
        }
        
        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            let decodedPorts = try JSONDecoder().decode([PortEntry].self, from: data)
            
            var tempDict: [Int: String] = [:]
            tempDict.reserveCapacity(decodedPorts.count)
            for entry in decodedPorts {
                tempDict[entry.port] = entry.service
            }
            self.portDictionary = tempDict
        } catch {
            print("[DatabaseService] Failed to parse ports.json: \(error)")
        }
    }
    
    private func loadVendorDatabase() {
        guard let url = Bundle.main.url(forResource: "oui_vendors", withExtension: "json") ??
                Bundle(for: Self.self).url(forResource: "oui_vendors", withExtension: "json") else {
            return
        }
        
        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            let decodedVendors = try JSONDecoder().decode([VendorEntry].self, from: data)
            
            var tempDict: [String: String] = [:]
            tempDict.reserveCapacity(decodedVendors.count)
            for entry in decodedVendors {
                if let normalized = normalizeOUIPrefix(entry.prefix) {
                    tempDict[normalized] = entry.vendor
                }
            }
            self.vendorDictionary = tempDict
        } catch {
            print("[DatabaseService] Failed to parse oui_vendors.json: \(error)")
        }
    }
    
    // MARK: - Helper Functions
    
    /// Normalizes a MAC string to the standard 3-octet uppercase format `"XX:XX:XX"`.
    private func normalizeOUIPrefix(_ input: String) -> String? {
        // Strip non-alphanumeric characters
        let cleaned = input.replacingOccurrences(of: "[:-]", with: "", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased()
        
        guard cleaned.count >= 6 else { return nil }
        
        let prefix6 = String(cleaned.prefix(6))
        let part1 = prefix6.prefix(2)
        let part2 = prefix6.dropFirst(2).prefix(2)
        let part3 = prefix6.dropFirst(4).prefix(2)
        
        return "\(part1):\(part2):\(part3)"
    }
}

// MARK: - Codable Data Transfer Objects

private struct PortEntry: Decodable {
    let port: Int
    let service: String
    let description: String?
}

private struct VendorEntry: Decodable {
    let prefix: String
    let vendor: String
}
