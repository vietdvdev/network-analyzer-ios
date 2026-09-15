//
//  HopResult.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation

/// Model representing a single intermediate router hop along the packet route.
public struct TracerouteHop: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let hopNumber: Int
    public let ipAddress: String?
    public let rtt: Double? // Round-Trip Time in milliseconds
    public let isTimeout: Bool
    
    public init(
        id: UUID = UUID(),
        hopNumber: Int,
        ipAddress: String?,
        rtt: Double?,
        isTimeout: Bool
    ) {
        self.id = id
        self.hopNumber = hopNumber
        self.ipAddress = ipAddress
        self.rtt = rtt
        self.isTimeout = isTimeout
    }
}
