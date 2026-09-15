//
//  PingStatistics.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation

/// Aggregated statistical summary computed from a series of ICMP ping results.
public struct PingStatistics: Sendable, Equatable {
    /// Total number of ICMP packets sent.
    public let packetsSent: Int
    
    /// Number of packets that received a valid reply.
    public let packetsReceived: Int
    
    /// Percentage of packets lost (0.0 – 100.0).
    public var packetLossPercent: Double {
        guard packetsSent > 0 else { return 0 }
        return Double(packetsSent - packetsReceived) / Double(packetsSent) * 100.0
    }
    
    /// Minimum observed RTT in milliseconds.
    public let minRTT: Double
    
    /// Maximum observed RTT in milliseconds.
    public let maxRTT: Double
    
    /// Arithmetic mean RTT in milliseconds.
    public let avgRTT: Double
    
    /// Jitter (mean deviation of RTT) in milliseconds.
    public let jitter: Double
    
    /// Initializes `PingStatistics` from a raw array of `PingResult`.
    public init(results: [PingResult]) {
        self.packetsSent = results.count
        
        let successfulResults = results.filter { $0.error == nil }
        self.packetsReceived = successfulResults.count
        
        let rttValues = successfulResults.map { $0.rtt }
        
        if rttValues.isEmpty {
            self.minRTT = 0
            self.maxRTT = 0
            self.avgRTT = 0
            self.jitter = 0
        } else {
            self.minRTT = rttValues.min() ?? 0
            self.maxRTT = rttValues.max() ?? 0
            
            let sum = rttValues.reduce(0, +)
            let average = sum / Double(rttValues.count)
            self.avgRTT = average
            
            // Jitter = Mean Absolute Deviation from average
            let deviationSum = rttValues.reduce(0) { $0 + abs($1 - average) }
            self.jitter = deviationSum / Double(rttValues.count)
        }
    }
}
