//
//  PortScanProfile.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation

/// Predefined port scan profiles providing curated or full-range target port lists.
public enum PortScanProfile: String, CaseIterable, Identifiable, Sendable {
    case topCommon = "Thông dụng (15 cổng)"
    case extended = "Mở rộng (30 cổng)"
    case fullRange = "Full Range (1–65535)"
    
    public var id: String { rawValue }
    
    /// Returns the array of port numbers corresponding to this profile.
    public var ports: [Int] {
        switch self {
        case .topCommon:
            return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
        case .extended:
            return [
                20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139,
                143, 161, 389, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389,
                5432, 5900, 8080, 8443
            ]
        case .fullRange:
            return Array(1...65535)
        }
    }
}
