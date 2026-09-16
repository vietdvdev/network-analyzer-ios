//
//  TracerouteEngine.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Darwin


/// Standard ICMP Header structure (RFC 792)
private struct ICMPHeader {
    var type: UInt8
    var code: UInt8
    var checksum: UInt16
    var identifier: UInt16
    var sequenceNumber: UInt16
}

/// High-performance hop-by-hop Traceroute engine leveraging unprivileged ICMP datagram sockets
/// and dynamic IP_TTL modification. Emits hops in real time using Swift's `AsyncStream`.
public final class TracerouteEngine: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = TracerouteEngine()
    
    public init() {}
    
    // MARK: - Protocol Constants
    
    private let icmpEchoRequestType: UInt8 = 8
    private let icmpTimeExceededType: UInt8 = 11
    private let icmpEchoReplyType: UInt8 = 0
    private let defaultMaxHops: Int = 30
    private let receiveTimeoutSeconds: time_t = 1
    private let payloadSize: Int = 32
    
    // MARK: - Public AsyncStream API
    
    /// Executes a traceroute to the specified target host, streaming each hop asynchronously as it is resolved.
    ///
    /// - Parameters:
    ///   - host: Hostname or IPv4 string (e.g., "8.8.8.8" or "cloudflare.com").
    ///   - maxHops: Maximum number of router hops to traverse (default is 30).
    /// - Returns: An `AsyncStream<TracerouteHop>` yielding hops sequentially until destination is reached or maxHops is exhausted.
    public func traceRoute(host: String, maxHops: Int = 30) -> AsyncStream<TracerouteHop> {
        return AsyncStream { continuation in
            let queue = DispatchQueue(label: "com.networkanalyzer.traceroute", qos: .userInitiated)
            
            queue.async { [weak self] in
                guard let self else {
                    continuation.finish()
                    return
                }
                
                self.performTraceroute(targetHost: host, maxHops: maxHops, continuation: continuation)
                continuation.finish()
            }
        }
    }
    
    // MARK: - Core Execution Routine
    
    private func performTraceroute(
        targetHost: String,
        maxHops: Int,
        continuation: AsyncStream<TracerouteHop>.Continuation
    ) {
        guard let destAddr = resolveHost(targetHost) else {
            continuation.yield(
                TracerouteHop(
                    hopNumber: 1,
                    ipAddress: nil,
                    rtt: nil,
                    isTimeout: true
                )
            )
            return
        }
        
        // Create unprivileged ICMP datagram socket
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard sock >= 0 else {
            return
        }
        
        defer {
            close(sock)
        }
        
        // Configure socket receive timeout
        var timeout = timeval(tv_sec: receiveTimeoutSeconds, tv_usec: 0)
        let setOptStatus = setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        guard setOptStatus == 0 else {
            return
        }
        
        let identifier = UInt16(truncatingIfNeeded: ProcessInfo.processInfo.processIdentifier)
        
        for hop in 1...maxHops {
            // Check cancellation
            var ttl = Int32(hop)
            
            // Set IP_TTL on the raw IP layer
            let ttlResult = setsockopt(
                sock,
                IPPROTO_IP,
                IP_TTL,
                &ttl,
                socklen_t(MemoryLayout<Int32>.size)
            )
            guard ttlResult == 0 else {
                continuation.yield(
                    TracerouteHop(hopNumber: hop, ipAddress: nil, rtt: nil, isTimeout: true)
                )
                continue
            }
            
            let packet = buildICMPPacket(identifier: identifier, sequenceNumber: UInt16(hop))
            
            let t1 = CFAbsoluteTimeGetCurrent()
            
            // Send ICMP Echo Request
            let sentBytes = packet.withUnsafeBytes { rawBuffer in
                var destCopy = destAddr
                return withUnsafePointer(to: &destCopy) { sockaddrPtr in
                    sockaddrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                        sendto(
                            sock,
                            rawBuffer.baseAddress,
                            rawBuffer.count,
                            0,
                            saPtr,
                            socklen_t(MemoryLayout<sockaddr_in>.size)
                        )
                    }
                }
            }
            
            if sentBytes < 0 {
                continuation.yield(
                    TracerouteHop(hopNumber: hop, ipAddress: nil, rtt: nil, isTimeout: true)
                )
                continue
            }
            
            // Receive buffer: IP Header (20 bytes min) + ICMP Header + Original IP/ICMP payload
            var receiveBuffer = [UInt8](repeating: 0, count: 512)
            var senderAddr = sockaddr_storage()
            var senderLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            
            let receivedBytes = withUnsafeMutablePointer(to: &senderAddr) { storagePtr in
                storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    recvfrom(
                        sock,
                        &receiveBuffer,
                        receiveBuffer.count,
                        0,
                        saPtr,
                        &senderLen
                    )
                }
            }
            
            let t2 = CFAbsoluteTimeGetCurrent()
            
            if receivedBytes < 0 {
                // Timeout or error reading socket
                continuation.yield(
                    TracerouteHop(hopNumber: hop, ipAddress: nil, rtt: nil, isTimeout: true)
                )
            } else {
                let rttMs = (t2 - t1) * 1000.0
                let senderIP = extractIPString(from: senderAddr)
                let icmpType = parseICMPType(from: receiveBuffer, bytesRead: receivedBytes)
                
                let currentHop = TracerouteHop(
                    hopNumber: hop,
                    ipAddress: senderIP,
                    rtt: rttMs,
                    isTimeout: false
                )
                continuation.yield(currentHop)
                
                // Destination reached via ICMP Echo Reply (Type 0)
                if icmpType == icmpEchoReplyType {
                    break
                }
            }
            
            // Subtle pacing between hops
            usleep(80_000) // 80ms
        }
    }
    
    // MARK: - Packet Parsing & Helpers
    
    /// Parses the ICMP Type from the received socket buffer.
    ///
    /// On Darwin `SOCK_DGRAM` ICMP sockets, the kernel might strip the outer IP header
    /// or retain it depending on whether an error was returned. We inspect both possibilities safely.
    private func parseICMPType(from buffer: [UInt8], bytesRead: Int) -> UInt8? {
        guard bytesRead >= 1 else { return nil }
        
        // In datagram ICMP sockets on macOS/iOS:
        // Case 1: The buffer begins directly with the ICMP header
        let directType = buffer[0]
        if directType == icmpEchoReplyType || directType == icmpTimeExceededType {
            return directType
        }
        
        // Case 2: Buffer retains IPv4 Header (Minimum 20 bytes). The IHL field gives exact IP header length.
        if bytesRead >= 20 {
            let ihl = Int(buffer[0] & 0x0F) * 4
            if bytesRead >= ihl + 1 {
                let icmpTypeAfterIP = buffer[ihl]
                return icmpTypeAfterIP
            }
        }
        
        return directType
    }
    
    /// Converts a received sockaddr_storage to human-readable IPv4 string.
    private func extractIPString(from storage: sockaddr_storage) -> String? {
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var storageCopy = storage
        // Cache ss_len before entering the unsafe pointer scope to avoid
        // Swift's Law of Exclusivity violation (overlapping read+write on storageCopy).
        let ssLen = socklen_t(storageCopy.ss_len)
        
        let conversionStatus = withUnsafePointer(to: &storageCopy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                getnameinfo(
                    saPtr,
                    ssLen,           // ← use the cached value, not storageCopy.ss_len
                    &hostBuffer,
                    socklen_t(hostBuffer.count),
                    nil,
                    0,
                    NI_NUMERICHOST
                )
            }
        }
        
        guard conversionStatus == 0 else { return nil }
        return String(cString: hostBuffer)
    }
    
    // MARK: - ICMP Packet Construction
    
    private func buildICMPPacket(identifier: UInt16, sequenceNumber: UInt16) -> Data {
        var header = ICMPHeader(
            type: icmpEchoRequestType,
            code: 0,
            checksum: 0,
            identifier: identifier.bigEndian,
            sequenceNumber: sequenceNumber.bigEndian
        )
        
        let payload = [UInt8](repeating: 0x42, count: payloadSize)
        var packetData = Data(bytes: &header, count: MemoryLayout<ICMPHeader>.size)
        packetData.append(contentsOf: payload)
        
        // Compute 16-bit one's complement checksum
        let checksum = computeChecksum(for: packetData)
        var checksumBigEndian = checksum
        let checksumBytes = Swift.withUnsafeBytes(of: &checksumBigEndian) { Array($0) }
        packetData[2] = checksumBytes[0]
        packetData[3] = checksumBytes[1]
        
        return packetData
    }
    
    private func computeChecksum(for data: Data) -> UInt16 {
        var sum: UInt32 = 0
        let count = data.count
        
        data.withUnsafeBytes { buffer in
            guard let ptr = buffer.bindMemory(to: UInt16.self).baseAddress else { return }
            let wordsCount = count / 2
            
            for i in 0..<wordsCount {
                sum += UInt32(ptr[i])
            }
            
            if count % 2 != 0 {
                let lastByte = buffer.load(fromByteOffset: count - 1, as: UInt8.self)
                sum += UInt32(lastByte)
            }
        }
        
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        
        return ~UInt16(sum)
    }
    
    // MARK: - DNS Host Resolver
    
    private func resolveHost(_ host: String) -> sockaddr_in? {
        var hints = addrinfo(
            ai_flags: AI_DEFAULT,
            ai_family: AF_INET,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: IPPROTO_ICMP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        
        var servinfo: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &servinfo)
        
        guard status == 0, let info = servinfo else {
            return nil
        }
        
        defer {
            freeaddrinfo(servinfo)
        }
        
        for ptr in sequence(first: info, next: { $0.pointee.ai_next }) {
            if ptr.pointee.ai_family == AF_INET, let addr = ptr.pointee.ai_addr {
                return addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }
        }
        
        return nil
    }
}
