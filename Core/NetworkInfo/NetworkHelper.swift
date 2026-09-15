//
//  NetworkHelper.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Darwin

/// Represents network addressing information for a specific interface.
public struct NetworkInterfaceInfo: Sendable, Equatable {
    /// Local IPv4 address representation (e.g., "192.168.1.15").
    public let ipAddress: String
    
    /// Subnet mask representation (e.g., "255.255.255.0").
    public let netmask: String
    
    /// Array of all usable host IP addresses within the subnet (excluding Network and Broadcast addresses).
    public let subnetRange: [String]
    
    public init(ipAddress: String, netmask: String, subnetRange: [String]) {
        self.ipAddress = ipAddress
        self.netmask = netmask
        self.subnetRange = subnetRange
    }
}

/// Helper singleton providing low-level POSIX socket and interface querying capabilities.
public final class NetworkHelper: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = NetworkHelper()
    
    private init() {}
    
    // MARK: - Constants
    
    /// Standard network interface identifier for Wi-Fi on iOS / iPadOS.
    private let wifiInterfaceName = "en0"
    
    // MARK: - Public APIs
    
    /// Queries the active Wi-Fi interface (`en0`) for IPv4 address, subnet mask, and all usable host IPs.
    ///
    /// This method traverses network interfaces using Darwin POSIX `getifaddrs` APIs,
    /// filtering for `AF_INET` family on `en0`, converts C sockaddr pointers
    /// to human-readable strings, and calculates the full usable IP subnet range.
    ///
    /// - Returns: A populated `NetworkInterfaceInfo` instance if successful, or `nil` if Wi-Fi is disconnected or unavailable.
    public func getLocalWiFiDetails() -> NetworkInterfaceInfo? {
        var ifaddrPointer: UnsafeMutablePointer<ifaddrs>?
        
        // Retrieve linked list of network interface addresses
        guard getifaddrs(&ifaddrPointer) == 0, let firstAddress = ifaddrPointer else {
            return nil
        }
        
        // Guarantee memory release upon exiting function scope
        defer {
            freeifaddrs(ifaddrPointer)
        }
        
        for ptr in sequence(first: firstAddress, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            
            // Check socket family: We only target IPv4 (AF_INET)
            guard let addr = interface.ifa_addr,
                  addr.pointee.sa_family == UInt8(AF_INET) else {
                continue
            }
            
            // Check interface name: Match against "en0"
            let name = String(cString: interface.ifa_name)
            guard name == wifiInterfaceName else {
                continue
            }
            
            // Convert ip address (ifa_addr) to string
            guard let ipString = convertSockAddrToIPString(addr) else {
                continue
            }
            
            // Convert subnet mask (ifa_netmask) to string
            guard let netmaskAddr = interface.ifa_netmask,
                  let netmaskString = convertSockAddrToIPString(netmaskAddr) else {
                continue
            }
            
            // Calculate usable host IP addresses within the subnet
            let subnetIPs = calculateSubnetIPs(ip: ipString, netmask: netmaskString)
            
            return NetworkInterfaceInfo(
                ipAddress: ipString,
                netmask: netmaskString,
                subnetRange: subnetIPs
            )
        }
        
        return nil
    }
    
    // MARK: - Private Logic & IP Math
    
    /// Computes all usable host IPv4 addresses in the subnet using bitwise operations.
    ///
    /// - Parameters:
    ///   - ip: IPv4 address string (e.g., "192.168.1.10").
    ///   - netmask: Subnet mask string (e.g., "255.255.255.0").
    /// - Returns: An ordered array of all usable host IP strings in the subnet.
    private func calculateSubnetIPs(ip: String, netmask: String) -> [String] {
        var ipAddr = in_addr()
        var maskAddr = in_addr()
        
        // Convert ASCII string to network byte order binary representation
        guard inet_aton(ip, &ipAddr) != 0,
              inet_aton(netmask, &maskAddr) != 0 else {
            return []
        }
        
        // Convert to Host Byte Order (Big Endian -> Host Order) for arithmetic manipulation
        let ipHost = UInt32(bigEndian: ipAddr.s_addr)
        let maskHost = UInt32(bigEndian: maskAddr.s_addr)
        
        // Bitwise IP Math:
        // Network Address = IP & Netmask
        // Broadcast Address = Network Address | (~Netmask)
        let networkAddress = ipHost & maskHost
        let broadcastAddress = networkAddress | (~maskHost)
        
        // Ensure there is at least one usable host address (e.g., handles point-to-point /31 or /32 safely)
        guard broadcastAddress > networkAddress + 1 else {
            return []
        }
        
        let startHost = networkAddress + 1
        let endHost = broadcastAddress - 1
        
        var availableIPs: [String] = []
        availableIPs.reserveCapacity(Int(endHost - startHost + 1))
        
        for host in startHost...endHost {
            // Convert host byte order back to network byte order
            var currentInAddr = in_addr(s_addr: host.bigEndian)
            if let cString = inet_ntoa(currentInAddr) {
                availableIPs.append(String(cString: cString))
            }
        }
        
        return availableIPs
    }
    
    /// Converts an UnsafePointer<sockaddr> to a numerical IP address string using `getnameinfo`.
    ///
    /// - Parameter socketAddress: Pointer to the C `sockaddr` struct.
    /// - Returns: Human-readable numerical string if conversion succeeds, otherwise `nil`.
    private func convertSockAddrToIPString(_ socketAddress: UnsafePointer<sockaddr>) -> String? {
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let sockLen = socklen_t(socketAddress.pointee.sa_len)
        
        let result = getnameinfo(
            socketAddress,
            sockLen,
            &hostBuffer,
            socklen_t(hostBuffer.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        
        guard result == 0 else {
            return nil
        }
        
        return String(cString: hostBuffer)
    }
}
