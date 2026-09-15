//
//  WebToolsView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Screen offering multi-record DNS Resolution (via DoH) and Domain/IP ownership lookups (via RDAP).
struct WebToolsView: View {
    
    // MARK: - State & Modes
    
    enum ToolMode: String, CaseIterable, Identifiable {
        case dns = "DNS Lookup"
        case whois = "Whois / RDAP"
        
        var id: String { rawValue }
    }
    
    @State private var selectedMode: ToolMode = .dns
    @State private var queryInput: String = "google.com"
    @State private var selectedDNSType: String = "A"
    
    @State private var isLoading: Bool = false
    @State private var dnsRecords: [DNSRecord] = []
    @State private var rdapTextResult: String = ""
    @State private var errorMessage: String?
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    private let dnsRecordTypes = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "CAA"]
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Segmented Mode Switcher
                modePicker
                
                // Input Form Card
                inputFormCard
                
                // Results Card
                if isLoading || !dnsRecords.isEmpty || !rdapTextResult.isEmpty || errorMessage != nil {
                    resultsCard
                }
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle("Công cụ Web & Tên miền")
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
    }
    
    // MARK: - Subviews
    
    private var modePicker: some View {
        Picker("Chế độ", selection: $selectedMode) {
            ForEach(ToolMode.allCases) { mode in
                Text(mode.rawValue).tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .onChange(of: selectedMode) { _, _ in
            errorMessage = nil
        }
    }
    
    private var inputFormCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(selectedMode == .dns ? "Tra cứu bản ghi DNS" : "Tra cứu quyền sở hữu RDAP")
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            
            HStack(spacing: 10) {
                Image(systemName: selectedMode == .dns ? "magnifyingglass" : "person.text.rectangle")
                    .foregroundStyle(accentColor)
                
                TextField(selectedMode == .dns ? "Tên miền (vd: apple.com)" : "Tên miền hoặc IP (vd: 1.1.1.1)", text: $queryInput)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .font(.subheadline)
            }
            .padding(12)
            .background(Color(uiColor: .tertiarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            
            // DNS Record Type Selector
            if selectedMode == .dns {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Loại bản ghi DNS:")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(dnsRecordTypes, id: \.self) { type in
                                Button {
                                    selectedDNSType = type
                                } label: {
                                    Text(type)
                                        .font(.caption)
                                        .fontWeight(.semibold)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .background(selectedDNSType == type ? accentColor : accentColor.opacity(0.12))
                                        .foregroundStyle(selectedDNSType == type ? .white : accentColor)
                                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            
            Button {
                executeLookup()
            } label: {
                HStack(spacing: 8) {
                    if isLoading {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.caption)
                    }
                    
                    Text(isLoading ? "Đang truy vấn..." : "Bắt đầu truy vấn")
                        .font(.headline)
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .foregroundStyle(.white)
                .background(isLoading || queryInput.trimmingCharacters(in: .whitespaces).isEmpty ? accentColor.opacity(0.6) : accentColor)
                .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            }
            .disabled(isLoading || queryInput.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
        )
    }
    
    private var resultsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(selectedMode == .dns ? "Kết quả bản ghi DNS" : "Kết quả RDAP")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                if selectedMode == .dns && !dnsRecords.isEmpty {
                    Text("\(dnsRecords.count) bản ghi")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            
            if isLoading {
                HStack(spacing: 8) {
                    ProgressView()
                        .tint(accentColor)
                    Text("Đang kết nối đến máy chủ resolver...")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 10)
            } else if let error = errorMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.subheadline)
                        .foregroundStyle(.red)
                }
                .padding(.vertical, 8)
            } else if selectedMode == .dns {
                if dnsRecords.isEmpty {
                    Text("Không tìm thấy bản ghi nào tương ứng.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 8)
                } else {
                    VStack(spacing: 8) {
                        ForEach(dnsRecords) { record in
                            dnsRecordRow(record)
                            if record.id != dnsRecords.last?.id {
                                Divider()
                            }
                        }
                    }
                }
            } else {
                // RDAP View
                Text(rdapTextResult)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(Color(uiColor: .label))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(.vertical, 4)
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
        )
    }
    
    private func dnsRecordRow(_ record: DNSRecord) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                // Indigo badge for record type
                Text("[\(record.type)]")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundStyle(accentColor)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(accentColor.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
                
                Text(record.name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .foregroundStyle(Color(uiColor: .label))
                    .lineLimit(1)
                
                Spacer()
                
                Text("TTL: \(record.ttl)s")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            
            Text(record.data)
                .font(.system(.subheadline, design: .monospaced))
                .fontWeight(.regular)
                .foregroundStyle(Color(uiColor: .secondaryLabel))
                .textSelection(.enabled)
        }
        .padding(.vertical, 3)
    }
    
    // MARK: - Actions
    
    private func executeLookup() {
        let target = queryInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { return }
        
        isLoading = true
        errorMessage = nil
        dnsRecords.removeAll()
        rdapTextResult = ""
        
        Task {
            do {
                if selectedMode == .dns {
                    let records = try await WebToolsEngine.shared.resolveDNS(domain: target, type: selectedDNSType)
                    await MainActor.run {
                        self.dnsRecords = records
                        self.isLoading = false
                    }
                } else {
                    let summary = try await WebToolsEngine.shared.lookupRDAP(query: target)
                    await MainActor.run {
                        self.rdapTextResult = summary
                        self.isLoading = false
                    }
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
}

#Preview {
    NavigationStack {
        WebToolsView()
    }
}
