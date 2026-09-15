//
//  PortScannerEngine.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Darwin

/// Enumeration describing the network reachability state of a target TCP port.
public enum PortState: String, Sendable, Equatable {
    case open = "Open"
    case closed = "Closed"
    case timeout = "Timeout"
}

/// Result model representing the diagnostic state of an inspected TCP port.
public struct PortResult: Sendable, Identifiable, Equatable {
    public var id: Int { port }
    public let port: Int
    public let state: PortState
    
    public init(port: Int, state: PortState) {
        self.port = port
        self.state = state
    }
}

/// High-performance TCP port scanner utilizing non-blocking POSIX sockets and Darwin multiplexing.
public final class PortScannerEngine: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = PortScannerEngine()
    
    public init() {}
    
    // MARK: - Constants
    
    /// Maximum concurrent socket descriptors to prevent EMFILE ("Too many open files") on iOS.
    private let maxConcurrencyLimit: Int = 45
    
    // MARK: - Public APIs
    
    /// Scans a collection of TCP ports concurrently against a target IP address.
    ///
    /// - Parameters:
    ///   - ip: Target IPv4 address string (e.g., "192.168.1.1").
    ///   - ports: Array of port numbers to evaluate (e.g., `[80, 443, 8080]`).
    /// - Returns: An ordered array of `PortResult` sorted by port number.
    public func scanPorts(ip: String, ports: [Int]) async -> [PortResult] {
        guard !ports.isEmpty else { return [] }
        
        var results: [PortResult] = []
        results.reserveCapacity(ports.count)
        
        await withTaskGroup(of: PortResult.self) { group in
            var portIterator = ports.makeIterator()
            let initialBatchSize = min(maxConcurrencyLimit, ports.count)
            
            // Prime the worker queue up to maxConcurrencyLimit
            for _ in 0..<initialBatchSize {
                if let nextPort = portIterator.next() {
                    group.addTask { [weak self] in
                        guard let self else { return PortResult(port: nextPort, state: .timeout) }
                        return await self.checkPort(ip: ip, port: nextPort)
                    }
                }
            }
            
            // As each probe concludes, harvest result and replenish slot
            for await result in group {
                results.append(result)
                
                if let nextPort = portIterator.next() {
                    group.addTask { [weak self] in
                        guard let self else { return PortResult(port: nextPort, state: .timeout) }
                        return await self.checkPort(ip: ip, port: nextPort)
                    }
                }
            }
        }
        
        return results.sorted { $0.port < $1.port }
    }
    
    // MARK: - Non-blocking TCP Socket Probe
    
    /// Evaluates a single TCP port using a non-blocking `connect()` and `select()` timeout multiplexer.
    ///
    /// - Parameters:
    ///   - ip: Target IPv4 address string.
    ///   - port: Port number (1...65535).
    ///   - timeoutMs: Millisecond deadline for TCP 3-way handshake completion.
    /// - Returns: `PortResult` with the classified `PortState`.
    private func checkPort(ip: String, port: Int, timeoutMs: Int = 500) async -> PortResult {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else {
                    continuation.resume(returning: PortResult(port: port, state: .timeout))
                    return
                }
                
                let state = self.performNonBlockingConnect(ip: ip, port: port, timeoutMs: timeoutMs)
                continuation.resume(returning: PortResult(port: port, state: state))
            }
        }
    }
    
    /// Low-level Darwin POSIX non-blocking socket connect routine.
    private func performNonBlockingConnect(ip: String, port: Int, timeoutMs: Int) -> PortState {
        // 1. Create standard TCP stream socket
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else {
            return .timeout
        }
        
        defer {
            close(sock)
        }
        
        // 2. Set socket to Non-blocking mode via fcntl
        let flags = fcntl(sock, F_GETFL, 0)
        guard flags >= 0, fcntl(sock, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            return .timeout
        }
        
        // 3. Configure target sockaddr_in
        var addr = sockaddr_in()
        addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        
        let conversionResult = inet_pton(AF_INET, ip, &addr.sin_addr)
        guard conversionResult == 1 else {
            return .closed
        }
        
        // 4. Initiate connect()
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(sock, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        
        // If connection immediately succeeded without waiting
        if connectResult == 0 {
            return .open
        }
        
        // EINPROGRESS indicates the non-blocking 3-way handshake has begun
        guard errno == EINPROGRESS else {
            if errno == ECONNREFUSED {
                return .closed
            }
            return .timeout
        }
        
        // 5. Initialize fd_set for select()
        var writeSet = fd_set()
        fdZero(&writeSet)
        fdSet(sock, &writeSet)
        
        let seconds = timeoutMs / 1000
        let microSeconds = (timeoutMs % 1000) * 1000
        var timeoutVal = timeval(tv_sec: time_t(seconds), tv_usec: suseconds_t(microSeconds))
        
        // 6. Wait for socket writability
        let selectResult = select(sock + 1, nil, &writeSet, nil, &timeoutVal)
        
        if selectResult > 0 {
            // Socket became writable; verify connection status using SO_ERROR
            var socketError: Int32 = 0
            var errorLen = socklen_t(MemoryLayout<Int32>.size)
            
            let optResult = getsockopt(sock, SOL_SOCKET, SO_ERROR, &socketError, &errorLen)
            if optResult == 0 {
                if socketError == 0 {
                    return .open
                } else if socketError == ECONNREFUSED {
                    return .closed
                } else {
                    return .timeout
                }
            }
            return .timeout
        } else if selectResult == 0 {
            // Timeout expired
            return .timeout
        } else {
            return .timeout
        }
    }
    
    // MARK: - POSIX fd_set Helpers
    
    /// Clears all bits in the fd_set structure.
    private func fdZero(_ set: inout fd_set) {
        set = fd_set()
    }
    
    /// Adds a file descriptor bit to the fd_set structure.
    private func fdSet(_ fd: Int32, _ set: inout fd_set) {
        let intOffset = Int(fd / 32)
        let bitOffset = fd % 32
        let mask = Int32(1 << bitOffset)
        
        withUnsafeMutablePointer(to: &set) { ptr in
            let rawPtr = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int32.self)
            rawPtr[intOffset] |= mask
        }
    }
}
