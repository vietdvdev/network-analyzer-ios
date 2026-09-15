//
//  PingEngine.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Darwin

/// Result representation for an individual ICMP Echo packet.
public struct PingResult: Sendable, Identifiable, Equatable {
    public var id: Int { sequence }
    public let sequence: Int
    public let rtt: Double // Round-Trip Time in milliseconds
    public let error: String? // Error description, or nil if successful
    
    public init(sequence: Int, rtt: Double, error: String? = nil) {
        self.sequence = sequence
        self.rtt = rtt
        self.error = error
    }
}

/// Standard ICMP Echo Header representation (RFC 792)
private struct ICMPHeader {
    var type: UInt8        // Type 8: ICMP Echo Request, Type 0: Echo Reply
    var code: UInt8        // Code 0
    var checksum: UInt16    // 16-bit one's complement checksum
    var identifier: UInt16  // Identifier to match requests and replies
    var sequenceNumber: UInt16 // Sequence counter
}

/// High-performance ICMP Ping engine executing unprivileged datagram socket operations on Darwin/iOS.
public final class PingEngine: @unchecked Sendable {
    
    // MARK: - Singleton
    
    public static let shared = PingEngine()
    
    public init() {}
    
    // MARK: - Constants
    
    private let icmpEchoRequestType: UInt8 = 8
    private let icmpEchoReplyType: UInt8 = 0
    private let payloadSize: Int = 32 // Standard 32-byte payload
    private let receiveTimeoutSeconds: time_t = 1
    
    // MARK: - Public APIs
    
    /// Executes a sequential ICMP Ping sweep against the target host or IP.
    ///
    /// - Parameters:
    ///   - host: Hostname (e.g. "apple.com") or IPv4 string (e.g. "1.1.1.1").
    ///   - count: Number of ICMP Echo Request packets to send (default is 4).
    /// - Returns: An array of `PingResult` containing sequence numbers, measured RTT in ms, or error states.
    public func startPing(host: String, count: Int = 4) async -> [PingResult] {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else {
                    continuation.resume(returning: [])
                    return
                }
                
                let results = self.executePing(target: host, count: count)
                continuation.resume(returning: results)
            }
        }
    }
    
    // MARK: - Private Socket Execution
    
    private func executePing(target: String, count: Int) -> [PingResult] {
        // Resolve hostname to IPv4 sockaddr_in
        guard let destAddr = resolveHost(target) else {
            return (0..<count).map { seq in
                PingResult(sequence: seq + 1, rtt: 0, error: "Cannot resolve target host")
            }
        }
        
        // Create unprivileged ICMP datagram socket (SOCK_DGRAM + IPPROTO_ICMP)
        // iOS prohibits SOCK_RAW for security reasons.
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard sock >= 0 else {
            let errorMsg = String(cString: strerror(errno))
            return (0..<count).map { seq in
                PingResult(sequence: seq + 1, rtt: 0, error: "Socket creation failed: \(errorMsg)")
            }
        }
        
        defer {
            close(sock)
        }
        
        // Configure socket receive timeout
        var timeout = timeval(tv_sec: receiveTimeoutSeconds, tv_usec: 0)
        let sockOptRes = setsockopt(
            sock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        guard sockOptRes == 0 else {
            return (0..<count).map { seq in
                PingResult(sequence: seq + 1, rtt: 0, error: "Failed to set socket timeout")
            }
        }
        
        let identifier = UInt16(truncatingIfNeeded: ProcessInfo.processInfo.processIdentifier)
        var results: [PingResult] = []
        
        for sequence in 1...count {
            let packetData = buildICMPPacket(identifier: identifier, sequenceNumber: UInt16(sequence))
            
            // Record start timestamp immediately before sendto()
            let t1 = CFAbsoluteTimeGetCurrent()
            
            let sentBytes = packetData.withUnsafeBytes { rawBuffer in
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
                let errorDesc = String(cString: strerror(errno))
                results.append(PingResult(sequence: sequence, rtt: 0, error: "Send failed: \(errorDesc)"))
                continue
            }
            
            // Receive buffer: IP Header (20-60 bytes) + ICMP Header (8 bytes) + Payload
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
            
            // Record completion timestamp
            let t2 = CFAbsoluteTimeGetCurrent()
            
            if receivedBytes < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    results.append(PingResult(sequence: sequence, rtt: 0, error: "Request timed out"))
                } else {
                    let errorDesc = String(cString: strerror(errno))
                    results.append(PingResult(sequence: sequence, rtt: 0, error: "Receive error: \(errorDesc)"))
                }
            } else {
                let rttMs = (t2 - t1) * 1000.0
                results.append(PingResult(sequence: sequence, rtt: rttMs, error: nil))
            }
            
            // Subtle pacing between successive ping sequences
            if sequence < count {
                usleep(100_000) // 100ms pause
            }
        }
        
        return results
    }
    
    // MARK: - Packet Crafting & Checksum
    
    /// Constructs a standard ICMP Echo Request packet with header and payload.
    private func buildICMPPacket(identifier: UInt16, sequenceNumber: UInt16) -> Data {
        var header = ICMPHeader(
            type: icmpEchoRequestType,
            code: 0,
            checksum: 0,
            identifier: identifier.bigEndian,
            sequenceNumber: sequenceNumber.bigEndian
        )
        
        // Construct arbitrary 32-byte payload pattern
        let payload = [UInt8](repeating: 0x41, count: payloadSize) // 'A'
        
        var packetData = Data(bytes: &header, count: MemoryLayout<ICMPHeader>.size)
        packetData.append(contentsOf: payload)
        
        // Compute 16-bit one's complement checksum
        let checksum = computeChecksum(for: packetData)
        
        // Write calculated checksum back into the ICMP header (offset 2..3)
        var checksumBigEndian = checksum
        let checksumBytes = Swift.withUnsafeBytes(of: &checksumBigEndian) { Array($0) }
        packetData[2] = checksumBytes[0]
        packetData[3] = checksumBytes[1]
        
        return packetData
    }
    
    /// Calculates the standard 16-bit one's complement checksum for IP/ICMP packets (RFC 1071).
    private func computeChecksum(for data: Data) -> UInt16 {
        var sum: UInt32 = 0
        let count = data.count
        
        data.withUnsafeBytes { buffer in
            guard let ptr = buffer.bindMemory(to: UInt16.self).baseAddress else { return }
            let wordsCount = count / 2
            
            for i in 0..<wordsCount {
                sum += UInt32(ptr[i])
            }
            
            // If data count is odd, pad the last odd byte
            if count % 2 != 0 {
                let lastByte = buffer.load(fromByteOffset: count - 1, as: UInt8.self)
                sum += UInt32(lastByte)
            }
        }
        
        // Fold 32-bit sum into 16-bit representation
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        
        // Take one's complement
        return ~UInt16(sum)
    }
    
    // MARK: - DNS Host Resolver
    
    /// Resolves target string (hostname or IP) to a sockaddr_in structure.
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
