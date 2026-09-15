//
//  DNSRecordTypes.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-15.
//

import Foundation

/// Representation of an individual resolved DNS record.
public struct DNSRecord: Identifiable, Sendable, Equatable {
    public var id: String { "\(name)-\(type)-\(data)" }
    public let type: String
    public let name: String
    public let data: String
    public let ttl: Int
    
    public init(type: String, name: String, data: String, ttl: Int) {
        self.type = type
        self.name = name
        self.data = data
        self.ttl = ttl
    }
}

/// Custom error types for DNS over HTTPS and RDAP queries.
public enum WebToolsError: LocalizedError, Sendable {
    case invalidURL
    case invalidResponse
    case notFound
    case rateLimited
    case serverError(statusCode: Int)
    case parsingError(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Định dạng tên miền hoặc địa chỉ IP không hợp lệ."
        case .invalidResponse:
            return "Máy chủ trả về phản hồi không hợp lệ."
        case .notFound:
            return "Không tìm thấy thông tin đăng ký cho mục tiêu này (404 Not Found)."
        case .rateLimited:
            return "Đã vượt quá giới hạn truy vấn (Rate Limited). Vui lòng thử lại sau giây lát."
        case .serverError(let statusCode):
            return "Máy chủ trả về mã lỗi HTTP \(statusCode)."
        case .parsingError(let message):
            return "Lỗi phân tích dữ liệu: \(message)"
        }
    }
}
