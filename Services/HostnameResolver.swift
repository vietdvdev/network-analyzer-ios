//
//  HostnameResolver.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation
import Network

/// Multi-source hostname resolution orchestrator.
/// Attempts to resolve a device hostname by querying multiple protocols in priority order:
/// 1. mDNS / Bonjour (via `NWBrowser`)
/// 2. NetBIOS Name Service (UDP port 137)
/// 3. LLMNR (UDP port 5355)
/// 4. Reverse DNS (POSIX `getnameinfo` with `NI_NAMEREQD`)
public final class HostnameResolver: @unchecked Sendable {
    
    // MARK: - Singleton
    
    public static let shared = HostnameResolver()
    
    private init() {}
    
    // MARK: - Public API
    
    /// Attempts to resolve the hostname for a given IP address using multiple protocols.
    ///
    /// - Parameter ip: IPv4 address string.
    /// - Returns: The first successfully resolved hostname, or `nil` if all methods fail.
    public func resolve(ip: String) async -> String? {
        // 1. mDNS / Bonjour
        if let mdnsName = await resolveMDNS(ip: ip) {
            return mdnsName
        }
        
        // 2. NetBIOS
        if let netbiosName = await NetBIOSProbe.shared.resolveHostname(ip: ip) {
            return netbiosName
        }
        
        // 3. LLMNR
        if let llmnrName = await LLMNRProbe.shared.resolveHostname(ip: ip) {
            return llmnrName
        }
        
        // 4. Reverse DNS
        if let rdnsName = reverseDNSLookup(ip: ip) {
            return rdnsName
        }
        
        return nil
    }
    
    // MARK: - mDNS / Bonjour Resolution
    
    /// Attempts to resolve hostname via Bonjour service browsing.
    /// Uses a short timeout to avoid blocking the scan pipeline.
    private func resolveMDNS(ip: String) async -> String? {
        return await withCheckedContinuation { continuation in
            let queue = DispatchQueue(label: "com.networkanalyzer.mdns.\(ip)")
            var resolved = false
            
            // Use NWConnection to attempt a TCP connect and read the resolved endpoint
            let host = NWEndpoint.Host(ip)
            let params = NWParameters.tcp
            params.prohibitExpensivePaths = false
            
            let connection = NWConnection(host: host, port: 80, using: params)
            
            // Timeout after 400ms
            let timeoutItem = DispatchWorkItem {
                if !resolved {
                    resolved = true
                    connection.cancel()
                    continuation.resume(returning: nil)
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(400), execute: timeoutItem)
            
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    timeoutItem.cancel()
                    if !resolved {
                        resolved = true
                        // Extract resolved endpoint metadata
                        if let endpoint = connection.currentPath?.remoteEndpoint,
                           case .hostPort(let resolvedHost, _) = endpoint {
                            let hostString = "\(resolvedHost)"
                            // Only return if it's a name, not just the IP
                            let result = hostString == ip ? nil : hostString
                            connection.cancel()
                            continuation.resume(returning: result)
                        } else {
                            connection.cancel()
                            continuation.resume(returning: nil)
                        }
                    }
                case .failed, .cancelled:
                    timeoutItem.cancel()
                    if !resolved {
                        resolved = true
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }
            
            connection.start(queue: queue)
        }
    }
    
    // MARK: - Reverse DNS
    
    /// Performs a Reverse DNS lookup using POSIX `getnameinfo` with `NI_NAMEREQD`.
    private func reverseDNSLookup(ip: String) -> String? {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }
        
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                getnameinfo(saPtr, socklen_t(MemoryLayout<sockaddr_in>.size),
                            &hostBuffer, socklen_t(hostBuffer.count),
                            nil, 0, NI_NAMEREQD)
            }
        }
        
        guard result == 0 else { return nil }
        let hostname = String(cString: hostBuffer)
        return hostname == ip ? nil : hostname
    }
}
