import AppKit
import SwiftUI

struct CodexActivityEntry: Decodable, Equatable, Identifiable {
    let sequence: Int
    let timestamp: String
    let kind: String
    let title: String
    let detail: String
    let state: String

    var id: Int { sequence }

    var timeLabel: String {
        guard let separator = timestamp.firstIndex(of: "T") else { return timestamp }
        return String(timestamp[timestamp.index(after: separator)...].prefix(8))
    }
}

struct CodexActivityView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let session: CodexActivitySession

    @State private var entries: [CodexActivityEntry] = []
    @State private var readError: String?

    private var activityURL: URL {
        session.attemptDirectory.appendingPathComponent("activity.jsonl")
    }

    private var terminalEntry: CodexActivityEntry? {
        entries.last { $0.state == "failed" || $0.kind == "complete" }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(22)

            Divider()

            activityFeed
                .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            footer
                .padding(16)
        }
        .frame(minWidth: 780, idealWidth: 880, minHeight: 560, idealHeight: 680)
        .task(id: session.id) {
            await followActivity()
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 15) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(headerTint.opacity(0.13))
                if model.isRunningCodexExploit {
                    ProgressView()
                        .controlSize(.regular)
                } else {
                    Image(systemName: terminalEntry?.state == "failed"
                        ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(headerTint)
                }
            }
            .frame(width: 48, height: 48)

            VStack(alignment: .leading, spacing: 6) {
                Text(model.isRunningCodexExploit
                    ? (session.isDynamic
                        ? "Codex is testing both binaries in the lab"
                        : "Codex is testing the patch")
                    : completionTitle)
                    .font(.title2.weight(.semibold))
                Text(session.isDynamic
                    ? (session.isHostDynamic
                        ? "Live commands and observations from this Mac’s contained sandbox"
                        : "Live commands and observations from the disposable macOS guest")
                    : "Live activity from the isolated exploit attempt")
                    .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    ActivityBoundaryBadge(
                        title: session.isHostDynamic
                            ? "Contained host lab"
                            : (session.isDynamic ? "Disposable UTM guest" : "Local sandbox"),
                        icon: session.isDynamic ? "shippingbox" : "macbook"
                    )
                    ActivityBoundaryBadge(title: "Network off", icon: "wifi.slash")
                    ActivityBoundaryBadge(
                        title: session.isDynamic ? "Old + patched staged" : "Target not launched",
                        icon: session.isDynamic ? "terminal" : "nosign"
                    )
                }
                .padding(.top, 3)
            }

            Spacer()

            TimelineView(.periodic(from: .now, by: 1)) { context in
                Text(elapsedLabel(at: context.date))
                    .font(.system(.callout, design: .monospaced).monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var activityFeed: some View {
        if entries.isEmpty {
            if model.isRunningCodexExploit {
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Preparing the activity stream…")
                        .foregroundStyle(.secondary)
                    if let readError {
                        Text(readError)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView(
                    "No Activity Stream",
                    systemImage: "clock.badge.questionmark",
                    description: Text("This completed attempt predates live activity tracking. Its result and audit remain available in the Exploit Lab.")
                )
            }
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(entries) { entry in
                            CodexActivityRow(
                                entry: entry,
                                isCurrent: model.isRunningCodexExploit
                                    && entry.id == entries.last?.id
                            )
                            .id(entry.id)
                            if entry.id != entries.last?.id {
                                Divider()
                                    .padding(.leading, 55)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
                }
                .onChange(of: entries.count) { _, _ in
                    if let last = entries.last {
                        withAnimation(.easeOut(duration: 0.2)) {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Attempt workspace")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(session.attemptDirectory.path)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer()
            Button("Open Directory") {
                NSWorkspace.shared.open(session.attemptDirectory)
            }
            .disabled(!FileManager.default.fileExists(atPath: session.attemptDirectory.path))
            Button(model.isRunningCodexExploit ? "Hide" : "Done") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private var headerTint: Color {
        if model.isRunningCodexExploit { return .purple }
        return terminalEntry?.state == "failed" ? .red : .green
    }

    private var completionTitle: String {
        terminalEntry?.state == "failed"
            ? "Codex attempt failed" : "Codex attempt completed"
    }

    private func elapsedLabel(at date: Date) -> String {
        let elapsed = max(0, Int(date.timeIntervalSince(session.startedAt)))
        return String(format: "%02d:%02d", elapsed / 60, elapsed % 60)
    }

    private func followActivity() async {
        while !Task.isCancelled {
            loadActivity()
            if !model.isRunningCodexExploit, terminalEntry != nil {
                break
            }
            try? await Task.sleep(for: .milliseconds(300))
        }
        loadActivity()
    }

    private func loadActivity() {
        guard FileManager.default.fileExists(atPath: activityURL.path) else { return }
        do {
            let text = try String(contentsOf: activityURL, encoding: .utf8)
            let decoder = JSONDecoder()
            let decoded = text.split(separator: "\n").compactMap { line in
                try? decoder.decode(CodexActivityEntry.self, from: Data(line.utf8))
            }
            if decoded != entries {
                entries = decoded
            }
            readError = nil
        } catch {
            readError = error.localizedDescription
        }
    }
}

struct ActivityBoundaryBadge: View {
    let title: String
    let icon: String

    var body: some View {
        Label(title, systemImage: icon)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(.quaternary, in: Capsule())
    }
}

struct CodexActivityRow: View {
    let entry: CodexActivityEntry
    let isCurrent: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 13) {
            ZStack {
                Circle()
                    .fill(tint.opacity(0.13))
                if isCurrent {
                    ProgressView()
                        .controlSize(.mini)
                } else {
                    Image(systemName: icon)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(tint)
                }
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .firstTextBaseline) {
                    Text(entry.title)
                        .font(.headline)
                    Spacer()
                    Text(entry.timeLabel)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
                if !entry.detail.isEmpty {
                    Text(entry.detail)
                        .font(entry.kind == "command" || entry.kind == "guest"
                            ? .system(.callout, design: .monospaced) : .callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 12)
    }

    private var tint: Color {
        if entry.state == "failed" { return .red }
        return switch entry.kind {
        case "evidence": .blue
        case "plan": .indigo
        case "analysis": .purple
        case "command": .orange
        case "artifact": .pink
        case "tool": .teal
        case "guest": .cyan
        case "result", "complete": .green
        case "error": .red
        default: .secondary
        }
    }

    private var icon: String {
        if entry.state == "failed" { return "exclamationmark" }
        return switch entry.kind {
        case "evidence": "doc.text.magnifyingglass"
        case "plan": "list.bullet.clipboard"
        case "analysis": "brain.head.profile"
        case "command": "terminal"
        case "artifact": "doc.badge.plus"
        case "tool": "hammer"
        case "guest": "shippingbox.and.arrow.backward"
        case "result": "text.badge.checkmark"
        case "complete": "checkmark"
        default: "circle.fill"
        }
    }
}
