//
//  NetBIOSProbe.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation
import Darwin

/// Sends a NetBIOS Name Service query (UDP port 137) to resolve Windows/Samba hostnames.
public final class NetBIOSProbe: @unchecked Sendable {
    
    // MARK: - Singleton
    
    public static let shared = NetBIOSProbe()
    
    private init() {}
    
    // MARK: - Constants
    
    /// NetBIOS Name Service standard port.
    private let netbiosPort: UInt16 = 137
    
    /// Probe timeout in milliseconds.
    private let timeoutMs: Int = 300
    
    // MARK: - Public API
    
    /// Queries the NetBIOS Name Service on a target IP to retrieve its hostname.
    ///
    /// - Parameter ip: Target IPv4 address string.
    /// - Returns: The resolved NetBIOS hostname, or `nil` if timed out or unavailable.
    public func resolveHostname(ip: String) async -> String? {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self else {
                    continuation.resume(returning: nil)
                    return
                }
                let name = self.performQuery(targetIP: ip)
                continuation.resume(returning: name)
            }
        }
    }
    
    // MARK: - NetBIOS Query Logic
    
    private func performQuery(targetIP: String) -> String? {
        // Create UDP socket
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return nil }
        
        defer {
            close(sock)
        }
        
        // Set receive timeout
        let seconds = timeoutMs / 1000
        let microseconds = (timeoutMs % 1000) * 1000
        var timeout = timeval(tv_sec: time_t(seconds), tv_usec: suseconds_t(microseconds))
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        
        // Build target address
        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = netbiosPort.bigEndian
        guard inet_pton(AF_INET, targetIP, &destAddr.sin_addr) == 1 else { return nil }
        
        // Build NetBIOS Name Query packet
        // Standard NBNS query for wildcard name "*" (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
        let queryPacket = buildNetBIOSNameQuery()
        
        // Send
        let sentBytes = queryPacket.withUnsafeBytes { rawBuffer in
            var destCopy = destAddr
            return withUnsafePointer(to: &destCopy) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    sendto(sock, rawBuffer.baseAddress, rawBuffer.count, 0, saPtr,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        
        guard sentBytes > 0 else { return nil }
        
        // Receive response
        var recvBuffer = [UInt8](repeating: 0, count: 1024)
        var senderAddr = sockaddr_storage()
        var senderLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        
        let receivedBytes = withUnsafeMutablePointer(to: &senderAddr) { storagePtr in
            storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                recvfrom(sock, &recvBuffer, recvBuffer.count, 0, saPtr, &senderLen)
            }
        }
        
        guard receivedBytes > 57 else { return nil } // Minimum valid response size
        
        return parseNetBIOSResponse(buffer: recvBuffer, length: Int(receivedBytes))
    }
    
    /// Builds a NetBIOS Name Service query for the wildcard name `*`.
    private func buildNetBIOSNameQuery() -> Data {
        var packet = Data()
        
        // Transaction ID (2 bytes) — arbitrary
        packet.append(contentsOf: [0x13, 0x37])
        // Flags (2 bytes) — Standard query
        packet.append(contentsOf: [0x00, 0x00])
        // Questions: 1
        packet.append(contentsOf: [0x00, 0x01])
        // Answer RRs, Authority RRs, Additional RRs: 0
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        
        // Question section: Encoded wildcard name "*"
        // NetBIOS first-level encoding: "*" → "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        // Length prefix: 32
        packet.append(0x20)
        
        let encodedWildcard: [UInt8] = [
            0x43, 0x4B, // "CK" = '*'
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // "AAAAAAAA" = padding
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41
        ]
        packet.append(contentsOf: encodedWildcard)
        
        // Null terminator
        packet.append(0x00)
        // Type: NBSTAT (0x0021)
        packet.append(contentsOf: [0x00, 0x21])
        // Class: IN (0x0001)
        packet.append(contentsOf: [0x00, 0x01])
        
        return packet
    }
    
    /// Parses the NetBIOS Name Service response to extract the first hostname entry.
    private func parseNetBIOSResponse(buffer: [UInt8], length: Int) -> String? {
        // Response structure:
        // Header (12 bytes) → Question section → Answer section
        // Skip to answer data: We need to find the NBSTAT answer resource record
        
        // Quick scan: The answer names start after the repeated question.
        // Typically at offset ~57+ in a standard NBSTAT response.
        // The number of names is at the byte after the RDLENGTH field.
        
        // Find the answer section by scanning past the question
        var offset = 12 // Skip header
        
        // Skip question name (look for 0x00 terminator)
        while offset < length && buffer[offset] != 0x00 {
            offset += 1
        }
        offset += 1 // Skip null terminator
        offset += 4 // Skip QTYPE (2) + QCLASS (2)
        
        // Now we're at the answer section
        // Skip answer name (may be compressed pointer 0xC0 0x0C)
        if offset + 2 < length && buffer[offset] == 0xC0 {
            offset += 2 // Compressed pointer
        } else {
            while offset < length && buffer[offset] != 0x00 { offset += 1 }
            offset += 1
        }
        
        offset += 4 // Skip TYPE (2) + CLASS (2)
        offset += 4 // Skip TTL (4)
        
        guard offset + 2 < length else { return nil }
        
        // RDLENGTH (2 bytes)
        offset += 2
        
        guard offset < length else { return nil }
        
        // Number of names (1 byte)
        let nameCount = Int(buffer[offset])
        offset += 1
        
        guard nameCount > 0, offset + 18 <= length else { return nil }
        
        // Each name entry: 15 bytes name + 1 byte suffix + 2 bytes flags = 18 bytes
        // Extract the first name (bytes 0-14, padded with spaces)
        let nameBytes = Array(buffer[offset..<(offset + 15)])
        
        if let rawName = String(bytes: nameBytes, encoding: .ascii) {
            let trimmed = rawName.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }
            return trimmed
        }
        
        return nil
    }
}
