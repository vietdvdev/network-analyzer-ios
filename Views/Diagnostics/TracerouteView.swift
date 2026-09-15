//
//  TracerouteView.swift
//  network-analyzer-ios
//
//  Created by Senior iOS UI/UX Developer on 2026-09-14.
//

import SwiftUI

/// Screen displaying real-time hop-by-hop packet route visualization streamed from `TracerouteEngine`.
struct TracerouteView: View {
    
    // MARK: - State
    
    @State private var targetInput: String = "8.8.8.8"
    @State private var maxHops: Int = 30
    @State private var isTracing: Bool = false
    @State private var hops: [TracerouteHop] = []
    
    // MARK: - Design System Constants
    
    private let accentColor: Color = .indigo
    private let minimalCornerRadius: CGFloat = 8
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Input Card
                inputSectionCard
                
                // Real-time Hops Stream Card
                if !hops.isEmpty || isTracing {
                    hopsSectionCard
                }
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle("Traceroute")
        .navigationBarTitleDisplayMode(.inline)
        .preferredColorScheme(.light)
    }
    
    // MARK: - Subviews
    
    private var inputSectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Mục tiêu định tuyến")
                .font(.caption)
                .fontWeight(.semibold)
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            
            HStack(spacing: 10) {
                Image(systemName: "point.topleft.down.to.point.bottomright.curvepath")
                    .foregroundStyle(accentColor)
                
                TextField("IP hoặc Hostname (vd: 8.8.8.8)", text: $targetInput)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .font(.subheadline)
            }
            .padding(12)
            .background(Color(uiColor: .tertiarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            
            Button {
                executeTraceroute()
            } label: {
                HStack(spacing: 8) {
                    if isTracing {
                        ProgressView()
                            .controlSize(.small)
                            .tint(.white)
                    } else {
                        Image(systemName: "play.fill")
                            .font(.caption)
                    }
                    
                    Text(isTracing ? "Đang dò đường đi gói tin..." : "Bắt đầu Traceroute")
                        .font(.headline)
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .foregroundStyle(.white)
                .background(isTracing || targetInput.trimmingCharacters(in: .whitespaces).isEmpty ? accentColor.opacity(0.6) : accentColor)
                .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
            }
            .disabled(isTracing || targetInput.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: minimalCornerRadius, style: .continuous)
                .stroke(Color(uiColor: .separator).opacity(0.3), lineWidth: 0.8)
        )
    }
    
    private var hopsSectionCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Danh sách các Hop trung gian")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                
                Spacer()
                
                Text("\(hops.count) hops")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            
            // Header Bar
            HStack {
                Text("HOP")
                    .frame(width: 38, alignment: .leading)
                Text("IP ROUTER")
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text("RTT")
                    .frame(width: 70, alignment: .trailing)
            }
            .font(.caption2)
            .fontWeight(.bold)
            .foregroundStyle(.secondary)
            
            Divider()
            
            VStack(spacing: 6) {
                ForEach(hops) { hop in
                    hopRow(hop)
                    if hop.id != hops.last?.id {
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
    
    private func hopRow(_ hop: TracerouteHop) -> some View {
        HStack {
            Text(String(format: "%02d", hop.hopNumber))
                .font(.system(.subheadline, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(.secondary)
                .frame(width: 38, alignment: .leading)
            
            if hop.isTimeout {
                Text("*  *  *  (Request timed out)")
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(Color(uiColor: .tertiaryLabel))
                    .frame(maxWidth: .infinity, alignment: .leading)
                
                Text("*")
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(Color.red)
                    .frame(width: 70, alignment: .trailing)
            } else {
                Text(hop.ipAddress ?? "Unknown")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(Color(uiColor: .label))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .lineLimit(1)
                
                if let rtt = hop.rtt {
                    Text("\(String(format: "%.1f", rtt)) ms")
                        .font(.system(.subheadline, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundStyle(rtt < 80 ? Color.green : Color.orange)
                        .frame(width: 70, alignment: .trailing)
                } else {
                    Text("-")
                        .font(.system(.subheadline, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(width: 70, alignment: .trailing)
                }
            }
        }
        .padding(.vertical, 3)
    }
    
    // MARK: - Actions
    
    private func executeTraceroute() {
        let target = targetInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else { return }
        
        isTracing = true
        hops.removeAll()
        
        Task {
            let stream = TracerouteEngine.shared.traceRoute(host: target, maxHops: maxHops)
            for await hop in stream {
                await MainActor.run {
                    self.hops.append(hop)
                }
            }
            await MainActor.run {
                self.isTracing = false
            }
        }
    }
}

#Preview {
    NavigationStack {
        TracerouteView()
    }
}
