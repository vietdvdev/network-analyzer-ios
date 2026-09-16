//
//  ArpTableReader.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//  Revised: iOS-compatible rewrite – all <net/route.h> types defined manually
//  because they are not exposed through the Swift/Darwin module on the iOS SDK.
//

import Foundation
import Darwin

// MARK: - Manual C Constants (from <net/route.h> / <net/if_dl.h>)
// These symbols exist in the header but are NOT available in the Swift Darwin
// overlay when compiling for the iOS SDK target.

/// sysctl sub-selector: dump ARP entries with a specific flag set.
private let kNET_RT_FLAGS: Int32 = 2

/// Routing flag: entry is an ARP / link-layer info record.
private let kRTF_LLINFO: Int32 = 0x400

/// rtm_addrs bit: destination address is present.
private let kRTA_DST: Int32 = 0x1

/// rtm_addrs bit: gateway (link-layer) address is present.
private let kRTA_GATEWAY: Int32 = 0x2

// MARK: - Manual C Struct Mirrors
// Must match the exact on-wire memory layout produced by the Darwin kernel
// on a 64-bit ARM (Apple Silicon / A-series) device or simulator.

/// Mirrors `struct rt_metrics` from <net/route.h> (8 × UInt32 + 7 × UInt32 = 56 bytes on arm64).
/// We only need its *size* to skip past it to reach the sockaddr array.
private struct RTMetrics {
    var rmx_locks: UInt32
    var rmx_mtu: UInt32
    var rmx_hopcount: UInt32
    var rmx_expire: Int32
    var rmx_recvpipe: UInt32
    var rmx_sendpipe: UInt32
    var rmx_ssthresh: UInt32
    var rmx_rtt: UInt32
    var rmx_rttvar: UInt32
    var rmx_pksent: UInt32
    var rmx_state: UInt32
    var rmx_filler: (UInt32, UInt32, UInt32)
}

/// Mirrors `struct rt_msghdr` from <net/route.h>.
private struct RTMsgHeader {
    var rtm_msglen: UInt16      // total length of this message
    var rtm_version: UInt8
    var rtm_type: UInt8
    var rtm_index: UInt16
    var _pad: UInt16            // compiler-inserted padding to align rtm_flags
    var rtm_flags: Int32
    var rtm_addrs: Int32        // bitmask of RTA_* present after header
    var rtm_pid: Int32
    var rtm_seq: Int32
    var rtm_errno: Int32
    var rtm_use: Int32
    var rtm_inits: UInt32
    var rtm_rmx: RTMetrics      // metrics (we skip this to reach sockaddrs)
}

// MARK: - ArpTableReader

/// Reads the kernel ARP cache via `sysctl` routing-table interface to map
/// IPv4 addresses to their MAC hardware addresses.
///
/// All `<net/route.h>` symbols are declared manually above because they are
/// not re-exported by the iOS SDK's Swift overlay for Darwin.
public final class ArpTableReader: @unchecked Sendable {

    // MARK: - Singleton

    public static let shared = ArpTableReader()

    private init() {}

    // MARK: - Public API

    /// Reads the system ARP table and returns a dictionary mapping IPv4 addresses
    /// to their corresponding MAC hardware addresses in colon-separated notation
    /// (e.g., `"AA:BB:CC:DD:EE:FF"`).
    ///
    /// - Returns: `[String: String]` where key = IPv4 string, value = MAC string.
    ///            Returns an empty dictionary if the sysctl call fails or the
    ///            sandbox denies access (expected on the iOS Simulator).
    public func readArpTable() -> [String: String] {
        var result: [String: String] = [:]

        // MIB: CTL_NET → PF_ROUTE → 0 → AF_INET → NET_RT_FLAGS → RTF_LLINFO
        var mib: [Int32] = [
            CTL_NET,
            PF_ROUTE,
            0,
            AF_INET,
            kNET_RT_FLAGS,
            kRTF_LLINFO
        ]

        // ── Step 1: query required buffer size ──────────────────────────────
        var bufferSize: size_t = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &bufferSize, nil, 0) == 0,
              bufferSize > 0 else {
            return result
        }

        // ── Step 2: allocate and fill buffer ────────────────────────────────
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferSize, alignment: 1)
        defer { buffer.deallocate() }

        guard sysctl(&mib, UInt32(mib.count), buffer, &bufferSize, nil, 0) == 0 else {
            return result
        }

        // ── Step 3: walk the sequence of rt_msghdr messages ─────────────────
        let headerSize = MemoryLayout<RTMsgHeader>.size
        var offset = 0

        while offset + headerSize <= bufferSize {
            let messagePtr = buffer.advanced(by: offset)
            let header = messagePtr.load(as: RTMsgHeader.self)
            let messageLength = Int(header.rtm_msglen)

            guard messageLength > headerSize else { break }

            // Only process messages that carry ARP / link-layer info
            if header.rtm_flags & kRTF_LLINFO != 0 {
                if let (ip, mac) = parseRoutingMessage(
                    messagePtr: messagePtr,
                    header: header,
                    totalLength: messageLength
                ) {
                    result[ip] = mac
                }
            }

            offset += messageLength
        }

        return result
    }

    // MARK: - Private Parsing

    /// Parses a single routing-table message, extracting the IPv4 destination
    /// and the link-layer (MAC) address from the trailing sockaddr array.
    private func parseRoutingMessage(
        messagePtr: UnsafeMutableRawPointer,
        header: RTMsgHeader,
        totalLength: Int
    ) -> (ip: String, mac: String)? {

        let headerSize = MemoryLayout<RTMsgHeader>.size
        guard totalLength > headerSize else { return nil }

        // sockaddr structs are laid out directly after the rt_msghdr
        var sockaddrPtr = messagePtr.advanced(by: headerSize)
        let endPtr = messagePtr.advanced(by: totalLength)
        let addrs = header.rtm_addrs

        var ipAddress: String?
        var macAddress: String?

        for bitIndex in 0..<8 {
            let rtaBit = Int32(1 << bitIndex)
            guard addrs & rtaBit != 0 else { continue }

            // Safety: ensure we have at least a sockaddr header
            guard sockaddrPtr < endPtr else { break }

            let sa = sockaddrPtr.load(as: sockaddr.self)
            let saLen = Int(sa.sa_len)
            guard saLen > 0 else { break }

            // ── Destination (IPv4) ──────────────────────────────────────────
            if rtaBit == kRTA_DST, sa.sa_family == UInt8(AF_INET) {
                let sinPtr = sockaddrPtr.assumingMemoryBound(to: sockaddr_in.self)
                var addr = sinPtr.pointee.sin_addr
                if let cStr = inet_ntoa(addr) {
                    ipAddress = String(cString: cStr)
                }

            // ── Gateway / Link-layer (MAC) ───────────────────────────────────
            } else if rtaBit == kRTA_GATEWAY, sa.sa_family == UInt8(AF_LINK) {
                let sdlPtr = sockaddrPtr.assumingMemoryBound(to: sockaddr_dl.self)
                let sdl = sdlPtr.pointee
                let nlen = Int(sdl.sdl_nlen)   // interface name length
                let alen = Int(sdl.sdl_alen)   // hardware address length

                if alen == 6 { // standard 6-byte Ethernet MAC
                    let macBytes: [UInt8] = withUnsafePointer(to: sdl.sdl_data) { dataPtr in
                        dataPtr.withMemoryRebound(to: UInt8.self, capacity: nlen + alen) { ptr in
                            (0..<alen).map { ptr[nlen + $0] }
                        }
                    }
                    let formatted = macBytes.map { String(format: "%02X", $0) }.joined(separator: ":")
                    if formatted != "00:00:00:00:00:00" {
                        macAddress = formatted
                    }
                }
            }

            // Advance to next sockaddr, rounded up to 4-byte alignment
            let aligned = (saLen + 3) & ~3
            sockaddrPtr = sockaddrPtr.advanced(by: max(aligned, 4))
        }

        guard let ip = ipAddress, let mac = macAddress else { return nil }
        return (ip, mac)
    }
}
