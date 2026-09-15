//
//  ArpTableReader.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation
import Darwin

/// Reads the kernel ARP cache via `sysctl` routing table interface to map IPv4 addresses to MAC hardware addresses.
public final class ArpTableReader: @unchecked Sendable {
    
    // MARK: - Singleton
    
    public static let shared = ArpTableReader()
    
    private init() {}
    
    // MARK: - Public API
    
    /// Reads the system ARP table and returns a dictionary mapping IPv4 addresses to their
    /// corresponding MAC hardware addresses in colon-separated notation (e.g., `"AA:BB:CC:DD:EE:FF"`).
    ///
    /// - Returns: `[String: String]` where key = IPv4 string, value = MAC string. Empty if unavailable.
    public func readArpTable() -> [String: String] {
        var result: [String: String] = [:]
        
        // sysctl MIB: CTL_NET -> PF_ROUTE -> 0 -> AF_INET -> NET_RT_FLAGS -> RTF_LLINFO
        var mib: [Int32] = [
            CTL_NET,
            PF_ROUTE,
            0,
            AF_INET,
            NET_RT_FLAGS,
            RTF_LLINFO
        ]
        
        // First call: determine required buffer size
        var bufferSize: size_t = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &bufferSize, nil, 0) == 0, bufferSize > 0 else {
            return result
        }
        
        // Allocate buffer and retrieve routing table data
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferSize, alignment: 1)
        defer {
            buffer.deallocate()
        }
        
        guard sysctl(&mib, UInt32(mib.count), buffer, &bufferSize, nil, 0) == 0 else {
            return result
        }
        
        // Walk through the routing messages
        var offset = 0
        while offset < bufferSize {
            let messagePtr = buffer.advanced(by: offset)
            
            // Read rt_msghdr to get the total message length
            let rtMsgHeader = messagePtr.load(as: rt_msghdr.self)
            let messageLength = Int(rtMsgHeader.rtm_msglen)
            
            guard messageLength > 0 else { break }
            
            // Only process RTM_GET type messages with valid address masks
            if rtMsgHeader.rtm_flags & RTF_LLINFO != 0 {
                if let (ip, mac) = parseRoutingMessage(messagePtr: messagePtr, length: messageLength) {
                    result[ip] = mac
                }
            }
            
            offset += messageLength
        }
        
        return result
    }
    
    // MARK: - Routing Message Parser
    
    /// Parses a single routing table message to extract the IPv4 address and link-layer (MAC) address.
    private func parseRoutingMessage(messagePtr: UnsafeMutableRawPointer, length: Int) -> (String, String)? {
        let headerSize = MemoryLayout<rt_msghdr>.size
        guard length > headerSize else { return nil }
        
        // sockaddr structures follow immediately after rt_msghdr
        var sockaddrPtr = messagePtr.advanced(by: headerSize)
        let rtMsgHeader = messagePtr.load(as: rt_msghdr.self)
        let addrs = rtMsgHeader.rtm_addrs
        
        var ipAddress: String?
        var macAddress: String?
        
        // Iterate through address fields indicated by rtm_addrs bitmask
        // RTA_DST = 0x1, RTA_GATEWAY = 0x2, etc.
        for i in 0..<8 {
            let rtaBit = Int32(1 << i)
            guard addrs & rtaBit != 0 else { continue }
            
            let sa = sockaddrPtr.load(as: sockaddr.self)
            let saLen = Int(sa.sa_len)
            guard saLen > 0 else { break }
            
            if rtaBit == RTA_DST && sa.sa_family == UInt8(AF_INET) {
                // Extract IPv4 destination address
                let sinPtr = sockaddrPtr.assumingMemoryBound(to: sockaddr_in.self)
                var addr = sinPtr.pointee.sin_addr
                if let cStr = inet_ntoa(addr) {
                    ipAddress = String(cString: cStr)
                }
            } else if rtaBit == RTA_GATEWAY && sa.sa_family == UInt8(AF_LINK) {
                // Extract MAC address from sockaddr_dl
                let sdlPtr = sockaddrPtr.assumingMemoryBound(to: sockaddr_dl.self)
                let sdl = sdlPtr.pointee
                let nlen = Int(sdl.sdl_nlen)
                let alen = Int(sdl.sdl_alen)
                
                if alen == 6 { // Standard Ethernet MAC (6 bytes)
                    let macBytes = withUnsafePointer(to: sdl.sdl_data) { dataPtr in
                        dataPtr.withMemoryRebound(to: UInt8.self, capacity: nlen + alen) { ptr in
                            (0..<alen).map { ptr[nlen + $0] }
                        }
                    }
                    macAddress = macBytes
                        .map { String(format: "%02X", $0) }
                        .joined(separator: ":")
                }
            }
            
            // Advance to next sockaddr (aligned to 4-byte boundary)
            let alignedLen = saLen > 0 ? ((saLen + 3) & ~3) : MemoryLayout<Int32>.size
            sockaddrPtr = sockaddrPtr.advanced(by: alignedLen)
        }
        
        guard let ip = ipAddress, let mac = macAddress, !mac.isEmpty else {
            return nil
        }
        
        return (ip, mac)
    }
}
