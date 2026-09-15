//
//  LLMNRProbe.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation
import Darwin

/// Sends a Link-Local Multicast Name Resolution (LLMNR) query (UDP port 5355)
/// to discover hostnames on the local subnet (RFC 4795).
public final class LLMNRProbe: @unchecked Sendable {
    
    // MARK: - Singleton
    
    public static let shared = LLMNRProbe()
    
    private init() {}
    
    // MARK: - Constants
    
    /// LLMNR standard multicast group address.
    private let llmnrMulticastGroup = "224.0.0.252"
    
    /// LLMNR standard port.
    private let llmnrPort: UInt16 = 5355
    
    /// Probe timeout in milliseconds.
    private let timeoutMs: Int = 300
    
    // MARK: - Public API
    
    /// Resolves the hostname of a target device via LLMNR reverse query.
    ///
    /// Sends a unicast LLMNR query directly to the target IP (rather than multicast)
    /// to resolve its hostname without flooding the entire network.
    ///
    /// - Parameter ip: Target IPv4 address string.
    /// - Returns: Resolved hostname or `nil` if timed out or no LLMNR responder found.
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
    
    // MARK: - LLMNR Query Logic
    
    private func performQuery(targetIP: String) -> String? {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return nil }
        
        defer {
            close(sock)
        }
        
        // Configure receive timeout
        let seconds = timeoutMs / 1000
        let microseconds = (timeoutMs % 1000) * 1000
        var timeout = timeval(tv_sec: time_t(seconds), tv_usec: suseconds_t(microseconds))
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        
        // Build reverse-lookup PTR query name from IP address
        // For example, IP "192.168.1.10" → labels: ["10", "1", "168", "192", "in-addr", "arpa"]
        let labels = buildReversePTRLabels(ip: targetIP)
        guard !labels.isEmpty else { return nil }
        
        // Build LLMNR DNS-format query
        let queryPacket = buildLLMNRQuery(labels: labels)
        
        // Send unicast to target IP on LLMNR port
        var destAddr = sockaddr_in()
        destAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = llmnrPort.bigEndian
        guard inet_pton(AF_INET, targetIP, &destAddr.sin_addr) == 1 else { return nil }
        
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
        var recvBuffer = [UInt8](repeating: 0, count: 512)
        var senderAddr = sockaddr_storage()
        var senderLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        
        let receivedBytes = withUnsafeMutablePointer(to: &senderAddr) { storagePtr in
            storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                recvfrom(sock, &recvBuffer, recvBuffer.count, 0, saPtr, &senderLen)
            }
        }
        
        guard receivedBytes > 12 else { return nil }
        
        return parseLLMNRResponse(buffer: recvBuffer, length: Int(receivedBytes))
    }
    
    /// Builds reversed PTR query labels from an IPv4 address string.
    private func buildReversePTRLabels(ip: String) -> [String] {
        let octets = ip.split(separator: ".").map(String.init)
        guard octets.count == 4 else { return [] }
        return octets.reversed() + ["in-addr", "arpa"]
    }
    
    /// Constructs an LLMNR query packet in standard DNS wire format (RFC 4795).
    private func buildLLMNRQuery(labels: [String]) -> Data {
        var packet = Data()
        
        // Transaction ID (2 bytes)
        packet.append(contentsOf: [0x00, 0x01])
        // Flags (2 bytes) — Standard query, no recursion (LLMNR: C bit = 0)
        packet.append(contentsOf: [0x00, 0x00])
        // QDCOUNT: 1
        packet.append(contentsOf: [0x00, 0x01])
        // ANCOUNT, NSCOUNT, ARCOUNT: 0
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        
        // Question: DNS name encoding
        for label in labels {
            let bytes = Array(label.utf8)
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(0x00) // Null terminator
        
        // QTYPE: PTR (0x000C)
        packet.append(contentsOf: [0x00, 0x0C])
        // QCLASS: IN (0x0001)
        packet.append(contentsOf: [0x00, 0x01])
        
        return packet
    }
    
    /// Parses an LLMNR/DNS PTR response to extract the resolved domain name.
    private func parseLLMNRResponse(buffer: [UInt8], length: Int) -> String? {
        guard length > 12 else { return nil }
        
        // Check ANCOUNT > 0
        let anCount = (UInt16(buffer[6]) << 8) | UInt16(buffer[7])
        guard anCount > 0 else { return nil }
        
        // Skip header (12 bytes)
        var offset = 12
        
        // Skip question section (traverse DNS name + QTYPE + QCLASS)
        offset = skipDNSName(buffer: buffer, offset: offset, length: length)
        offset += 4 // QTYPE + QCLASS
        
        guard offset < length else { return nil }
        
        // Read answer section
        // Skip answer name (may be compressed pointer)
        offset = skipDNSName(buffer: buffer, offset: offset, length: length)
        offset += 2 // TYPE
        offset += 2 // CLASS
        offset += 4 // TTL
        
        guard offset + 2 <= length else { return nil }
        
        // RDLENGTH
        offset += 2
        
        guard offset < length else { return nil }
        
        // RDATA for PTR: a DNS name
        return readDNSName(buffer: buffer, offset: offset, length: length)
    }
    
    /// Skips a DNS encoded name and returns the new offset.
    private func skipDNSName(buffer: [UInt8], offset: Int, length: Int) -> Int {
        var pos = offset
        while pos < length {
            let labelLen = Int(buffer[pos])
            if labelLen == 0 {
                return pos + 1
            } else if (labelLen & 0xC0) == 0xC0 {
                return pos + 2 // Compressed pointer (2 bytes)
            } else {
                pos += 1 + labelLen
            }
        }
        return pos
    }
    
    /// Reads and decodes a DNS wire-format name into a dotted string.
    private func readDNSName(buffer: [UInt8], offset: Int, length: Int) -> String? {
        var labels: [String] = []
        var pos = offset
        
        while pos < length {
            let labelLen = Int(buffer[pos])
            if labelLen == 0 {
                break
            } else if (labelLen & 0xC0) == 0xC0 {
                // Compressed pointer
                guard pos + 1 < length else { break }
                let pointerOffset = Int((UInt16(buffer[pos] & 0x3F) << 8) | UInt16(buffer[pos + 1]))
                if let deref = readDNSName(buffer: buffer, offset: pointerOffset, length: length) {
                    labels.append(deref)
                }
                break
            } else {
                pos += 1
                guard pos + labelLen <= length else { break }
                if let label = String(bytes: buffer[pos..<(pos + labelLen)], encoding: .utf8) {
                    labels.append(label)
                }
                pos += labelLen
            }
        }
        
        let result = labels.joined(separator: ".")
        return result.isEmpty ? nil : result
    }
}
