//
//  LANScannerViewModel.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation
import Network
import Observation

/// Model representing a discovered device on the local network.
public struct DiscoveredDevice: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let ipAddress: String
    public var hostname: String?
    public var macAddress: String?
    public var vendorName: String?
    public var isAlive: Bool
    
    public init(
        id: UUID = UUID(),
        ipAddress: String,
        hostname: String? = nil,
        macAddress: String? = nil,
        vendorName: String? = nil,
        isAlive: Bool = true
    ) {
        self.id = id
        self.ipAddress = ipAddress
        self.hostname = hostname
        self.macAddress = macAddress
        self.vendorName = vendorName
        self.isAlive = isAlive
    }
}

/// ViewModel coordinating local area network discovery using structured concurrency and TCP port probing.
@Observable
@MainActor
public final class LANScannerViewModel {
    
    // MARK: - Observable Properties
    
    public var devices: [DiscoveredDevice] = []
    public var isScanning: Bool = false
    public var progress: Double = 0.0
    
    // MARK: - Configuration Constants
    
    /// Maximum concurrent TCP connections allowed to respect iOS file descriptor limits.
    private let maxConcurrentProbes: Int = 45
    
    /// Target ports commonly open or responsive on consumer & enterprise devices (HTTP, SMB).
    private let probePorts: [NWEndpoint.Port] = [80, 445]
    
    /// Connection probe timeout in milliseconds.
    private let probeTimeoutMs: Int = 450
    
    // MARK: - Scanning Control
    
    private var scanTask: Task<Void, Never>?
    
    public init() {}
    
    /// Starts the asynchronous LAN scanning sequence.
    public func startScan() {
        guard !isScanning else { return }
        
        scanTask?.cancel()
        scanTask = Task { [weak self] in
            await self?.executeScan()
        }
    }
    
    /// Stops the running LAN scan.
    public func stopScan() {
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }
    
    // MARK: - Scan Execution Engine
    
    private func executeScan() async {
        isScanning = true
        devices.removeAll()
        progress = 0.0
        
        guard let wifiInfo = NetworkHelper.shared.getLocalWiFiDetails(),
              !wifiInfo.subnetRange.isEmpty else {
            isScanning = false
            return
        }
        
        let targetIPs = wifiInfo.subnetRange
        let totalHosts = targetIPs.count
        var scannedCount = 0
        
        // Use bounded concurrency via TaskGroup to prevent file descriptor exhaustion
        await withTaskGroup(of: DiscoveredDevice?.self) { group in
            var ipIterator = targetIPs.makeIterator()
            
            // Prime the initial batch up to maxConcurrentProbes
            for _ in 0..<min(maxConcurrentProbes, totalHosts) {
                if let nextIP = ipIterator.next() {
                    group.addTask { [weak self] in
                        guard let self else { return nil }
                        return await self.checkHost(ip: nextIP)
                    }
                }
            }
            
            // As each task finishes, harvest result and replenish with the next pending IP
            for await device in group {
                if Task.isCancelled {
                    group.cancelAll()
                    break
                }
                
                scannedCount += 1
                self.progress = Double(scannedCount) / Double(totalHosts)
                
                if let device, device.isAlive {
                    self.devices.append(device)
                    // Keep the device list sorted by IPv4 numerical address
                    self.devices.sort { self.compareIPs($0.ipAddress, $1.ipAddress) }
                }
                
                // Replenish slot
                if let nextIP = ipIterator.next() {
                    group.addTask { [weak self] in
                        guard let self else { return nil }
                        return await self.checkHost(ip: nextIP)
                    }
                }
            }
        }
        
        self.progress = 1.0
        
        // Post-scan enrichment: ARP MAC addresses + Vendor names + Hostnames
        if !Task.isCancelled {
            await enrichDevicesWithARP()
            await enrichDevicesWithHostnames()
        }
        
        self.isScanning = false
    }
    
    // MARK: - Post-Scan Enrichment
    
    /// Reads the kernel ARP cache and populates MAC address + vendor name for each discovered device.
    private func enrichDevicesWithARP() async {
        let arpTable = ArpTableReader.shared.readArpTable()
        guard !arpTable.isEmpty else { return }
        
        for i in devices.indices {
            let ip = devices[i].ipAddress
            if let mac = arpTable[ip] {
                devices[i].macAddress = mac
                devices[i].vendorName = DatabaseService.shared.getVendorName(macPrefix: mac)
            }
        }
    }
    
    /// Attempts hostname resolution for each discovered device via NetBIOS, LLMNR, and Reverse DNS.
    private func enrichDevicesWithHostnames() async {
        await withTaskGroup(of: (Int, String?).self) { group in
            for (index, device) in devices.enumerated() {
                guard device.hostname == nil else { continue }
                
                group.addTask {
                    // Try NetBIOS first (best for Windows/Samba)
                    if let name = await NetBIOSProbe.shared.resolveHostname(ip: device.ipAddress) {
                        return (index, name)
                    }
                    // Try LLMNR
                    if let name = await LLMNRProbe.shared.resolveHostname(ip: device.ipAddress) {
                        return (index, name)
                    }
                    // Fallback: Reverse DNS via getnameinfo
                    if let name = self.reverseDNSLookup(ip: device.ipAddress) {
                        return (index, name)
                    }
                    return (index, nil)
                }
            }
            
            for await (index, hostname) in group {
                if index < devices.count, let resolvedName = hostname {
                    devices[index].hostname = resolvedName
                }
            }
        }
    }
    
    /// Performs a Reverse DNS lookup using POSIX `getnameinfo` with `NI_NAMEREQD`.
    private nonisolated func reverseDNSLookup(ip: String) -> String? {
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
        // Filter out raw IP echoes (getnameinfo may return the IP itself)
        return hostname == ip ? nil : hostname
    }
    
    // MARK: - TCP Port Probing via NWConnection
    
    /// Probes an IP address over well-known ports with a short deadline.
    /// Returns a `DiscoveredDevice` if the host responds or explicitly rejects the connection.
    private nonisolated func checkHost(ip: String) async -> DiscoveredDevice? {
        // Probe ports sequentially or return as soon as one indicates host presence
        for port in probePorts {
            if Task.isCancelled { return nil }
            
            let isResponsive = await probeEndpoint(ip: ip, port: port, timeoutMs: probeTimeoutMs)
            if isResponsive {
                return DiscoveredDevice(ipAddress: ip, hostname: nil, isAlive: true)
            }
        }
        
        return nil
    }
    
    /// Probes a single (IP, Port) endpoint using Apple's `Network.framework`.
    ///
    /// Both `.ready` (Open) and `.failed` with connection refused (ECONNREFUSED / POSIX 61)
    /// confirm that the remote host is alive and responding on the network.
    private nonisolated func probeEndpoint(ip: String, port: NWEndpoint.Port, timeoutMs: Int) async -> Bool {
        return await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(ip)
            let params = NWParameters.tcp
            params.prohibitExpensivePaths = false
            
            let connection = NWConnection(host: host, port: port, using: params)
            let queue = DispatchQueue(label: "lan.scanner.probe.\(ip).\(port.rawValue)")
            
            // Thread-safe state to ensure single resumption of continuation
            final class ProbeState: @unchecked Sendable {
                var isCompleted = false
                let lock = NSLock()
                
                func complete(with result: Bool) -> Bool {
                    lock.lock()
                    defer { lock.unlock() }
                    if !isCompleted {
                        isCompleted = true
                        return true
                    }
                    return false
                }
            }
            
            let probeState = ProbeState()
            
            // Timeout timer via GCD
            let timeoutWorkItem = DispatchWorkItem {
                if probeState.complete(with: false) {
                    connection.cancel()
                    continuation.resume(returning: false)
                }
            }
            
            queue.asyncAfter(
                deadline: .now() + .milliseconds(timeoutMs),
                execute: timeoutWorkItem
            )
            
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Host is alive and port is OPEN
                    timeoutWorkItem.cancel()
                    if probeState.complete(with: true) {
                        connection.cancel()
                        continuation.resume(returning: true)
                    }
                    
                case .failed(let error):
                    timeoutWorkItem.cancel()
                    // If connection is refused (ECONNREFUSED / POSIX error 61), the host is alive!
                    let isHostAlive: Bool
                    if case .posix(let code) = error {
                        isHostAlive = (code == .ECONNREFUSED)
                    } else {
                        isHostAlive = false
                    }
                    
                    if probeState.complete(with: isHostAlive) {
                        connection.cancel()
                        continuation.resume(returning: isHostAlive)
                    }
                    
                case .cancelled:
                    timeoutWorkItem.cancel()
                    if probeState.complete(with: false) {
                        continuation.resume(returning: false)
                    }
                    
                default:
                    break
                }
            }
            
            connection.start(queue: queue)
        }
    }
    
    // MARK: - Sorting Helper
    
    /// Compares two IPv4 address strings numerically.
    private func compareIPs(_ ip1: String, _ ip2: String) -> Bool {
        let octets1 = ip1.split(separator: ".").compactMap { UInt32($0) }
        let octets2 = ip2.split(separator: ".").compactMap { UInt32($0) }
        
        guard octets1.count == 4, octets2.count == 4 else {
            return ip1 < ip2
        }
        
        for i in 0..<4 {
            if octets1[i] != octets2[i] {
                return octets1[i] < octets2[i]
            }
        }
        return false
    }
}
