//
//  PortScannerView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Screen enabling user to execute non-blocking TCP sweeps against standard or custom port ranges,
/// integrating offline IANA service descriptions from `DatabaseService`.
struct PortScannerView: View {
    
    // MARK: - State
    
    @State private var ipInput: String = "192.168.1.1"
    @State private var selectedProfile: ScanProfile = .topCommon
    @State private var isScanning: Bool = false
    @State private var scanResults: [PortResult] = []
    
    // MARK: - Port Profiles
    
    enum ScanProfile: String, CaseIterable, Identifiable {
        case topCommon = "Thông dụng (15 cổng)"
        case extended = "Mở rộng (30 cổng)"
        
        var id: String { rawValue }
        
        var ports: [Int] {
            switch self {
            case .topCommon:
                return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
            case .extended:
                return [
                    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139,
                    143, 161, 389, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389,
                    5432, 5900, 8080, 8443
                ]
            }
        }
    }
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    
    // MARK: - Filtered Open Ports
    
    private var openPorts: [PortResult] {
        scanResults.filter { $0.state == .open }
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Input & Profile Card
                inputSectionCard
                
                // Discovered Open Ports Card
                if !scanResults.isEmpty || isScanning {
                    resultsSectionCard
                }
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle("Port Scanner")
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
    }
    
    // MARK: - Subviews
    
    private var inputSectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Địa chỉ mục tiêu")
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            
            HStack(spacing: 10) {
                Image(systemName: "desktopcomputer")
                    .foregroundStyle(accentColor)
                
                TextField("IPv4 (vd: 192.168.1.1)", text: $ipInput)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.numbersAndPunctuation)
                    .font(.subheadline)
            }
            .padding(12)
            .background(Color(uiColor: .tertiarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            
            VStack(alignment: .leading, spacing: 8) {
                Text("Dải cổng quét:")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                
                Picker("Dải cổng", selection: $selectedProfile) {
                    ForEach(ScanProfile.allCases) { profile in
                        Text(profile.rawValue).tag(profile)
                    }
                }
                .pickerStyle(.segmented)
            }
            
            Button {
                executePortScan()
            } label: {
                HStack(spacing: 8) {
                    if isScanning {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: "bolt.fill")
                            .font(.caption)
                    }
                    
                    Text(isScanning ? "Đang quét cổng TCP..." : "Bắt đầu quét cổng")
                        .font(.headline)
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .foregroundStyle(.white)
                .background(isScanning || ipInput.trimmingCharacters(in: .whitespaces).isEmpty ? accentColor.opacity(0.6) : accentColor)
                .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            }
            .disabled(isScanning || ipInput.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
        )
    }
    
    private var resultsSectionCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Cổng đang mở (Open Ports)")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                if !isScanning {
                    Text("\(openPorts.count) cổng mở")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundStyle(openPorts.isEmpty ? .secondary : accentColor)
                        .monospacedDigit()
                }
            }
            
            if openPorts.isEmpty {
                VStack(spacing: 8) {
                    if isScanning {
                        HStack(spacing: 8) {
                            ProgressView()
                                .tint(accentColor)
                            Text("Đang phân tích phản hồi TCP handshake...")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 12)
                    } else {
                        VStack(spacing: 6) {
                            Image(systemName: "lock.slash")
                                .font(.title3)
                                .foregroundStyle(.secondary)
                            Text("Không phát hiện cổng nào mở trong dải đã quét.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                    }
                }
            } else {
                VStack(spacing: 8) {
                    ForEach(openPorts) { result in
                        portResultRow(result)
                        if result.id != openPorts.last?.id {
                            Divider()
                        }
                    }
                }
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
    
    private func portResultRow(_ result: PortResult) -> some View {
        let serviceName = resolveServiceName(for: result.port)
        
        return HStack {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(accentColor.opacity(0.12))
                        .frame(width: 36, height: 36)
                    
                    Image(systemName: "lock.open.fill")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(accentColor)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("Port \(result.port)")
                            .font(.subheadline)
                            .fontWeight(.bold)
                            .foregroundStyle(Color(uiColor: .label))
                            .monospacedDigit()
                        
                        // Service tag badge
                        Text(serviceName)
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .foregroundStyle(accentColor)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(accentColor.opacity(0.1))
                            .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
                    }
                    
                    Text("TCP Service")
                        .font(.caption)
                        .foregroundStyle(Color(uiColor: .secondaryLabel))
                }
            }
            
            Spacer()
            
            HStack(spacing: 6) {
                Circle()
                    .fill(Color.green)
                    .frame(width: 8, height: 8)
                
                Text("Open")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundStyle(Color.green)
            }
        }
        .padding(.vertical, 4)
    }
    
    // MARK: - Service Lookup Integration
    
    /// Queries DatabaseService offline registry for IANA service name, with local fallback.
    private func resolveServiceName(for port: Int) -> String {
        if let offlineService = DatabaseService.shared.getServiceName(port: port) {
            return offlineService
        }
        return "Unknown Service"
    }
    
    // MARK: - Actions
    
    private func executePortScan() {
        let target = ipInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { return }
        
        isScanning = true
        scanResults.removeAll()
        
        let targetPorts = selectedProfile.ports
        
        Task {
            let results = await PortScannerEngine.shared.scanPorts(ip: target, ports: targetPorts)
            await MainActor.run {
                self.scanResults = results
                self.isScanning = false
            }
        }
    }
}

#Preview {
    NavigationStack {
        PortScannerView()
    }
}
