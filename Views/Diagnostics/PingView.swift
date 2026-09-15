//
//  PingView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Screen enabling user to configure and execute ICMP Ping sweeps against a host or IP.
struct PingView: View {
    
    // MARK: - Init
    
    var prefillHost: String?
    
    // MARK: - State
    
    @State private var hostInput: String = "1.1.1.1"
    @State private var pingCount: Int = 4
    @State private var isPinging: Bool = false
    @State private var pingResults: [PingResult] = []
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Input & Configuration Card
                inputSectionCard
                
                // Results Section
                if !pingResults.isEmpty || isPinging {
                    resultsSectionCard
                }
                
                // Statistics Summary
                if !pingResults.isEmpty && !isPinging {
                    statisticsCard
                }
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle("ICMP Ping")
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
        .onAppear {
            if let prefill = prefillHost {
                hostInput = prefill
            }
        }
    }
    
    // MARK: - Subviews
    
    private var inputSectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Mục tiêu kiểm tra")
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            
            HStack(spacing: 10) {
                Image(systemName: "globe")
                    .foregroundStyle(accentColor)
                
                TextField("IP hoặc Hostname (vd: apple.com)", text: $hostInput)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .font(.subheadline)
            }
            .padding(12)
            .background(Color(uiColor: .tertiarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            
            HStack {
                Text("Số gói tin gửi:")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Picker("Số lượng", selection: $pingCount) {
                    Text("4").tag(4)
                    Text("8").tag(8)
                    Text("16").tag(16)
                }
                .pickerStyle(.segmented)
                .frame(width: 150)
            }
            
            Button {
                executePing()
            } label: {
                HStack(spacing: 8) {
                    if isPinging {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: "play.fill")
                            .font(.caption)
                    }
                    
                    Text(isPinging ? "Đang gửi gói ICMP..." : "Bắt đầu Ping")
                        .font(.headline)
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .foregroundStyle(.white)
                .background(isPinging || hostInput.trimmingCharacters(in: .whitespaces).isEmpty ? accentColor.opacity(0.6) : accentColor)
                .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            }
            .disabled(isPinging || hostInput.trimmingCharacters(in: .whitespaces).isEmpty)
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
                Text("Kết quả phản hồi")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                if !pingResults.isEmpty {
                    let successfulPings = pingResults.filter { $0.error == nil }
                    let lossRate = Int((Double(pingResults.count - successfulPings.count) / Double(pingResults.count)) * 100)
                    Text("Loss: \(lossRate)%")
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundStyle(lossRate > 0 ? .red : .secondary)
                        .monospacedDigit()
                }
            }
            
            VStack(spacing: 8) {
                ForEach(pingResults) { result in
                    pingResultRow(result)
                    if result.id != pingResults.last?.id {
                        Divider()
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
    
    private func pingResultRow(_ result: PingResult) -> some View {
        HStack {
            Text("#\(result.sequence)")
                .font(.subheadline)
                .fontWeight(.bold)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(width: 32, alignment: .leading)
            
            if let error = result.error {
                Text(error)
                    .font(.subheadline)
                    .foregroundStyle(.red)
                
                Spacer()
                
                Circle()
                    .fill(Color.red)
                    .frame(width: 8, height: 8)
            } else {
                Text("\(String(format: "%.1f", result.rtt)) ms")
                    .font(.subheadline)
                    .fontWeight(.bold)
                    .monospacedDigit()
                    .foregroundStyle(result.rtt < 80 ? Color.green : Color.orange)
                
                Spacer()
                
                Circle()
                    .fill(result.rtt < 80 ? Color.green : Color.orange)
                    .frame(width: 8, height: 8)
            }
        }
        .padding(.vertical, 4)
    }
    
    private var statisticsCard: some View {
        let stats = PingStatistics(results: pingResults)
        
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "chart.bar.fill")
                    .foregroundStyle(accentColor)
                Text("Thống kê tổng hợp")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 12) {
                statCell(title: "Min", value: String(format: "%.1f ms", stats.minRTT), color: .green)
                statCell(title: "Avg", value: String(format: "%.1f ms", stats.avgRTT), color: accentColor)
                statCell(title: "Max", value: String(format: "%.1f ms", stats.maxRTT), color: .orange)
            }
            
            Divider()
            
            HStack {
                InfoRow(title: "Jitter", value: String(format: "%.2f ms", stats.jitter), isMonospaced: true)
            }
            Divider()
            HStack {
                InfoRow(
                    title: "Packet Loss",
                    value: String(format: "%.0f%% (%d/%d)", stats.packetLossPercent, stats.packetsReceived, stats.packetsSent),
                    isMonospaced: true
                )
            }
        }
        .cardStyle()
    }
    
    private func statCell(title: String, value: String, color: Color) -> some View {
        VStack(spacing: 4) {
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline)
                .fontWeight(.bold)
                .monospacedDigit()
                .foregroundStyle(color)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color(uiColor: .tertiarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
    }
    
    // MARK: - Actions
    
    private func executePing() {
        let target = hostInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { return }
        
        isPinging = true
        pingResults.removeAll()
        
        Task {
            let results = await PingEngine.shared.startPing(host: target, count: pingCount)
            await MainActor.run {
                self.pingResults = results
                self.isPinging = false
            }
        }
    }
}

#Preview {
    NavigationStack {
        PingView()
    }
}
