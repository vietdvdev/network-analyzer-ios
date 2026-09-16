//
//  WebToolsEngine.swift
//  network-analyzer-ios
//
//  Created by Senior iOS Core Developer on 2026-09-14.
//

import Foundation


/// High-performance Web Tools Engine handling DNS-over-HTTPS (DoH) and REST-based RDAP ownership lookups.
public final class WebToolsEngine: @unchecked Sendable {
    
    // MARK: - Singleton Instance
    
    public static let shared = WebToolsEngine()
    
    private let urlSession: URLSession
    
    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 8.0
        configuration.timeoutIntervalForResource = 12.0
        self.urlSession = URLSession(configuration: configuration)
    }
    
    // MARK: - DNS Over HTTPS (DoH) Resolver
    
    /// Resolves DNS records via Cloudflare DoH (DNS-over-HTTPS) JSON API.
    ///
    /// - Parameters:
    ///   - domain: Fully qualified domain name (e.g., "apple.com").
    ///   - type: DNS record type string (e.g. "A", "AAAA", "MX", "TXT", "CNAME", "NS").
    /// - Returns: Array of resolved `DNSRecord` instances.
    public func resolveDNS(domain: String, type: String = "A") async throws -> [DNSRecord] {
        let trimmedDomain = domain.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedType = type.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        
        guard !trimmedDomain.isEmpty,
              var components = URLComponents(string: "https://cloudflare-dns.com/dns-query") else {
            throw WebToolsError.invalidURL
        }
        
        components.queryItems = [
            URLQueryItem(name: "name", value: trimmedDomain),
            URLQueryItem(name: "type", value: trimmedType)
        ]
        
        guard let url = components.url else {
            throw WebToolsError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw WebToolsError.invalidResponse
        }
        
        switch httpResponse.statusCode {
        case 200...299:
            break
        case 404:
            throw WebToolsError.notFound
        case 429:
            throw WebToolsError.rateLimited
        default:
            throw WebToolsError.serverError(statusCode: httpResponse.statusCode)
        }
        
        do {
            let decoder = JSONDecoder()
            let dohResponse = try decoder.decode(DoHResponse.self, from: data)
            
            guard let answers = dohResponse.Answer, !answers.isEmpty else {
                return []
            }
            
            return answers.map { answer in
                let readableType = mapDNSTypeCodeToString(answer.type)
                let cleanedData = answer.data.replacingOccurrences(of: "\"", with: "")
                return DNSRecord(
                    type: readableType,
                    name: answer.name,
                    data: cleanedData,
                    ttl: answer.TTL
                )
            }
        } catch {
            throw WebToolsError.parsingError(error.localizedDescription)
        }
    }
    
    // MARK: - RDAP / Whois Resolver
    
    /// Queries the standardized REST-based RDAP registry for domain or IP registration details.
    ///
    /// - Parameter query: Domain name (e.g. "google.com") or IP address (e.g. "1.1.1.1").
    /// - Returns: Formatted text summarizing registrar, status, important events (creation, expiration), and nameservers.
    public func lookupRDAP(query: String) async throws -> String {
        let target = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            throw WebToolsError.invalidURL
        }
        
        let isIP = isIPAddress(target)
        let endpoint = isIP ? "https://rdap.org/ip/\(target)" : "https://rdap.org/domain/\(target)"
        
        guard let url = URL(string: endpoint) else {
            throw WebToolsError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
        
        let (data, response) = try await urlSession.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw WebToolsError.invalidResponse
        }
        
        switch httpResponse.statusCode {
        case 200...299:
            break
        case 404:
            throw WebToolsError.notFound
        case 429:
            throw WebToolsError.rateLimited
        default:
            throw WebToolsError.serverError(statusCode: httpResponse.statusCode)
        }
        
        do {
            let decoder = JSONDecoder()
            let rdapData = try decoder.decode(RDAPResponse.self, from: data)
            return formatRDAPSummary(rdap: rdapData, target: target, isIP: isIP)
        } catch {
            // Fallback: If strict structure decoding fails, attempt basic dictionary summary
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return formatFallbackRDAP(json: json, target: target)
            }
            throw WebToolsError.parsingError("Không thể định dạng dữ liệu phản hồi RDAP.")
        }
    }
    
    // MARK: - Formatting & Helpers
    
    private func formatRDAPSummary(rdap: RDAPResponse, target: String, isIP: Bool) -> String {
        var lines: [String] = []
        lines.append("=== THÔNG TIN ĐĂNG KÝ RDAP ===")
        lines.append("Mục tiêu: \(target) (\(isIP ? "Địa chỉ IP" : "Tên miền"))")
        
        if let handle = rdap.handle {
            lines.append("Mã định danh (Handle): \(handle)")
        }
        
        if let ldhName = rdap.ldhName {
            lines.append("Tên miền (LDH): \(ldhName)")
        }
        
        if let status = rdap.status, !status.isEmpty {
            lines.append("Trạng thái: \(status.joined(separator: ", "))")
        }
        
        // Registrar info from entities
        if let entities = rdap.entities {
            for entity in entities {
                if let roles = entity.roles, roles.contains("registrar") {
                    let name = entity.vcardArray?.extractFullName() ?? entity.handle ?? "Không rõ"
                    lines.append("Nhà đăng ký (Registrar): \(name)")
                }
            }
        }
        
        // Important Lifecycle Events
        if let events = rdap.events, !events.isEmpty {
            lines.append("\n--- Các mốc thời gian quan trọng ---")
            for event in events {
                let actionDesc = mapEventAction(event.eventAction)
                lines.append("• \(actionDesc): \(formatDateString(event.eventDate))")
            }
        }
        
        // Nameservers
        if let nameservers = rdap.nameservers, !nameservers.isEmpty {
            lines.append("\n--- Hệ thống Nameservers ---")
            for ns in nameservers {
                if let name = ns.ldhName {
                    lines.append("• \(name)")
                }
            }
        }
        
        return lines.joined(separator: "\n")
    }
    
    private func formatFallbackRDAP(json: [String: Any], target: String) -> String {
        var lines: [String] = []
        lines.append("=== THÔNG TIN ĐĂNG KÝ RDAP ===")
        lines.append("Mục tiêu: \(target)")
        if let handle = json["handle"] as? String {
            lines.append("Mã định danh (Handle): \(handle)")
        }
        if let status = json["status"] as? [String] {
            lines.append("Trạng thái: \(status.joined(separator: ", "))")
        }
        return lines.joined(separator: "\n")
    }
    
    private func isIPAddress(_ str: String) -> Bool {
        var sin = sockaddr_in()
        var sin6 = sockaddr_in6()
        return inet_pton(AF_INET, str, &sin.sin_addr) == 1 || inet_pton(AF_INET6, str, &sin6.sin6_addr) == 1
    }
    
    private func mapEventAction(_ action: String) -> String {
        switch action.lowercased() {
        case "registration": return "Ngày đăng ký khởi tạo"
        case "expiration": return "Ngày hết hạn"
        case "last changed": return "Cập nhật lần cuối"
        case "transfer": return "Chuyển nhượng"
        default: return action.capitalized
        }
    }
    
    private func formatDateString(_ raw: String) -> String {
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        
        if let date = isoFormatter.date(from: raw) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .medium
            displayFormatter.timeStyle = .short
            displayFormatter.locale = Locale(identifier: "vi_VN")
            return displayFormatter.string(from: date)
        }
        return raw
    }
    
    private func mapDNSTypeCodeToString(_ typeCode: Int) -> String {
        switch typeCode {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 257: return "CAA"
        default: return "TYPE\(typeCode)"
        }
    }
}

// MARK: - DoH Models

private struct DoHResponse: Decodable {
    let Status: Int
    let TC: Bool?
    let RD: Bool?
    let RA: Bool?
    let AD: Bool?
    let CD: Bool?
    let Answer: [DoHAnswer]?
}

private struct DoHAnswer: Decodable {
    let name: String
    let type: Int
    let TTL: Int
    let data: String
}

// MARK: - RDAP Models

private struct RDAPResponse: Decodable {
    let handle: String?
    let ldhName: String?
    let status: [String]?
    let entities: [RDAPEntity]?
    let events: [RDAPEvent]?
    let nameservers: [RDAPNameserver]?
}

private struct RDAPEntity: Decodable {
    let handle: String?
    let roles: [String]?
    let vcardArray: [AnyCodable]?
}

private struct RDAPEvent: Decodable {
    let eventAction: String
    let eventDate: String
}

private struct RDAPNameserver: Decodable {
    let ldhName: String?
}

// Helper for dynamic vCard array parsing in RDAP RFC 7483
private enum AnyCodable: Decodable {
    case string(String)
    case array([AnyCodable])
    case other
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let stringVal = try? container.decode(String.self) {
            self = .string(stringVal)
        } else if let arrayVal = try? container.decode([AnyCodable].self) {
            self = .array(arrayVal)
        } else {
            self = .other
        }
    }
}

private extension Array where Element == AnyCodable {
    func extractFullName() -> String? {
        guard self.count >= 2, case .array(let properties) = self[1] else { return nil }
        for prop in properties {
            if case .array(let item) = prop, item.count >= 4 {
                if case .string(let key) = item[0], key.lowercased() == "fn" {
                    if case .string(let fnValue) = item[3] {
                        return fnValue
                    }
                }
            }
        }
        return nil
    }
}
