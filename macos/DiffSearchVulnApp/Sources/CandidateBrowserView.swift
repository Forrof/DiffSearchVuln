import AppKit
import DiffSearchVulnCore
import SwiftUI

struct CandidateBrowserView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            candidateHeader
            Divider()
            if let page = model.candidatePage {
                candidatePicker(page)
                Divider()
                evidencePane
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.isLoadingCandidates {
                ProgressView("Validating candidate catalog…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView {
                    Label("Choose a Semantic Diff", systemImage: "point.3.connected.trianglepath.dotted")
                } description: {
                    Text("Select a completed diff directory to browse every changed function and its evidence.")
                } actions: {
                    Button("Choose Diff…") { chooseDiffDirectory() }
                        .buttonStyle(.borderedProminent)
                    if model.acceptanceFixtureAvailable {
                        Button("Use rclone Acceptance Fixture") {
                            model.useAcceptanceFixture()
                        }
                    }
                }
            }
        }
        .navigationTitle("Function Diff")
    }

    private var candidateHeader: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Changed-function evidence")
                    .font(.headline)
                    .lineLimit(1)
                if let page = model.candidatePage {
                    Text("\(page.totalCount.formatted()) candidates preserved · showing ranks \(page.offset + 1)–\(min(page.offset + page.candidates.count, page.totalCount))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if model.isLoadingCandidates { ProgressView().controlSize(.small) }
            Button("Choose Diff…") { chooseDiffDirectory() }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 11)
    }

    private func candidatePicker(_ page: WorkerCandidatePage) -> some View {
        HStack(spacing: 12) {
            Text("Candidate")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Picker(
                "Candidate",
                selection: Binding(
                    get: { model.selectedCandidateID ?? page.candidates.first?.id ?? "" },
                    set: { identifier in
                        model.selectCandidate(page.candidates.first { $0.id == identifier })
                    }
                )
            ) {
                ForEach(page.candidates) { candidate in
                    Text("#\(candidate.deterministicRank)  \(FunctionNameDisplay.compact(candidate.primaryName))")
                        .tag(candidate.id)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .frame(minWidth: 330, idealWidth: 440, maxWidth: 520)
            .help(selectedCandidate(in: page)?.primaryName ?? "Choose a changed function")
            if let candidate = selectedCandidate(in: page) {
                CandidateKindBadge(kind: candidate.matchKind)
            }

            Spacer()
            Button {
                model.loadCandidates(
                    directory: model.diffDirectoryURL!,
                    offset: max(0, page.offset - page.limit)
                )
            } label: {
                Label("Previous 50", systemImage: "chevron.left")
            }
            .disabled(page.offset == 0 || model.isLoadingCandidates)
            Text("Page \(page.offset / page.limit + 1)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            Button {
                model.loadCandidates(
                    directory: model.diffDirectoryURL!,
                    offset: page.offset + page.limit
                )
            } label: {
                Label("Next 50", systemImage: "chevron.right")
            }
            .labelStyle(.titleAndIcon)
            .disabled(page.offset + page.candidates.count >= page.totalCount || model.isLoadingCandidates)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.55))
    }

    private func selectedCandidate(in page: WorkerCandidatePage) -> WorkerCandidate? {
        page.candidates.first { $0.id == model.selectedCandidateID }
    }

    @ViewBuilder
    private var evidencePane: some View {
        if model.isLoadingEvidence {
            ProgressView("Materializing complete evidence…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let evidence = model.selectedEvidence {
            EvidenceDetailView(evidence: evidence)
        } else {
            ContentUnavailableView(
                "Select a Candidate",
                systemImage: "doc.text.magnifyingglass",
                description: Text("The complete old/new decompilation will be loaded from the local analysis cache.")
            )
        }
    }

    private func chooseDiffDirectory() {
        let panel = NSOpenPanel()
        panel.title = "Choose Completed Semantic Diff"
        panel.prompt = "Choose"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            model.loadCandidates(directory: url)
        }
    }
}

struct CandidateRow: View {
    let candidate: WorkerCandidate

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .firstTextBaseline) {
                Text("#\(candidate.deterministicRank)")
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                Text(FunctionNameDisplay.compact(candidate.primaryName))
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text(candidate.deterministicScore.formatted(.number.precision(.fractionLength(1))))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 7) {
                CandidateKindBadge(kind: candidate.matchKind)
                if !candidate.changeEvidence.advisoryTermsMatched.isEmpty {
                    Text(candidate.changeEvidence.advisoryTermsMatched.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Text("Δ \(candidate.changeEvidence.instructionCountDelta, format: .number.sign(strategy: .always())) ins")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 5)
        .help(candidate.primaryName)
    }
}

enum FunctionNameDisplay {
    static func compact(_ name: String) -> String {
        let pathTail = name.split(separator: "/").last.map(String.init) ?? name
        if pathTail.count <= 68 { return pathTail }
        return String(pathTail.suffix(68))
    }

    static func context(_ name: String) -> String? {
        let components = name.split(separator: "/")
        guard components.count > 1 else { return nil }
        return components.dropLast().suffix(2).joined(separator: "/")
    }
}

struct CandidateKindBadge: View {
    let kind: String

    var body: some View {
        Text(kind.replacingOccurrences(of: "_", with: " "))
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(tint.opacity(0.13), in: Capsule())
            .foregroundStyle(tint)
    }

    private var tint: Color {
        switch kind {
        case "added": .green
        case "deleted": .red
        case "modified": .blue
        case "data_only": .orange
        default: .secondary
        }
    }
}

struct EvidenceDetailView: View {
    let evidence: WorkerEvidenceDossier

    var body: some View {
        let codeDiff = SideBySideCodeDiff(
            oldText: decompilationText(for: evidence.oldRecord),
            newText: decompilationText(for: evidence.newRecord)
        )
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Text(FunctionNameDisplay.compact(evidence.candidate.primaryName))
                    .font(.title3.weight(.semibold))
                    .textSelection(.enabled)
                    .help(evidence.candidate.primaryName)
                HStack(spacing: 10) {
                    if let context = FunctionNameDisplay.context(evidence.candidate.primaryName) {
                        Text(context)
                            .font(.caption.monospaced())
                            .foregroundStyle(.tertiary)
                    }
                    Label("Rank \(evidence.candidate.deterministicRank)", systemImage: "list.number")
                    Label(
                        evidence.candidate.deterministicScore.formatted(.number.precision(.fractionLength(1))),
                        systemImage: "gauge.with.dots.needle.67percent"
                    )
                    Label(evidence.candidate.matchKind, systemImage: "arrow.left.arrow.right")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            Divider()
            HSplitView {
                DecompilationPane(
                    title: "Previous · removed lines",
                    record: evidence.oldRecord,
                    lines: codeDiff.oldLines,
                    tint: .red
                )
                DecompilationPane(
                    title: "Updated · added lines",
                    record: evidence.newRecord,
                    lines: codeDiff.newLines,
                    tint: .green
                )
            }
            .frame(maxHeight: .infinity)
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func decompilationText(for record: WorkerFunctionRecord?) -> String? {
        guard let record else { return nil }
        return record.function.decompilation ?? "Decompilation unavailable"
    }
}

struct DecompilationPane: View {
    let title: String
    let record: WorkerFunctionRecord?
    let lines: [CodeDiffLine]
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(title)
                    .font(.headline)
                    .foregroundStyle(tint)
                Spacer()
                if let record {
                    Text("0x\(record.function.address)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            Divider()
            if record != nil {
                GeometryReader { geometry in
                    ScrollView([.horizontal, .vertical]) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(lines) { line in
                                CodeDiffLineView(
                                    line: line,
                                    minimumWidth: geometry.size.width
                                )
                            }
                        }
                        .fixedSize(horizontal: true, vertical: false)
                        .padding(.vertical, 8)
                    }
                }
            } else {
                ContentUnavailableView(
                    title.hasPrefix("Previous") ? "Added Function" : "Deleted Function",
                    systemImage: title.hasPrefix("Previous") ? "plus.circle" : "minus.circle"
                )
            }
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }
}

enum CodeLineChange: Equatable {
    case unchanged
    case removed
    case added
}

struct CodeDiffLine: Identifiable {
    let number: Int
    let text: String
    let change: CodeLineChange

    var id: String { "\(number)-\(change)-\(text)" }
}

struct SideBySideCodeDiff {
    let oldLines: [CodeDiffLine]
    let newLines: [CodeDiffLine]

    init(oldText: String?, newText: String?) {
        let old = oldText?.components(separatedBy: .newlines) ?? []
        let new = newText?.components(separatedBy: .newlines) ?? []
        let difference = new.difference(from: old)
        var removedOffsets = Set<Int>()
        var addedOffsets = Set<Int>()
        for change in difference {
            switch change {
            case .remove(let offset, _, _):
                removedOffsets.insert(offset)
            case .insert(let offset, _, _):
                addedOffsets.insert(offset)
            }
        }
        oldLines = old.enumerated().map { offset, text in
            CodeDiffLine(
                number: offset + 1,
                text: text,
                change: removedOffsets.contains(offset) ? .removed : .unchanged
            )
        }
        newLines = new.enumerated().map { offset, text in
            CodeDiffLine(
                number: offset + 1,
                text: text,
                change: addedOffsets.contains(offset) ? .added : .unchanged
            )
        }
    }
}

struct CodeDiffLineView: View {
    let line: CodeDiffLine
    let minimumWidth: CGFloat

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Text("\(line.number)")
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(.tertiary)
                .frame(width: 48, alignment: .trailing)
                .padding(.trailing, 8)
            Text(marker)
                .font(.system(size: 11.5, design: .monospaced).weight(.bold))
                .foregroundStyle(markerColor)
                .frame(width: 22)
            Text(line.text.isEmpty ? " " : line.text)
                .font(.system(size: 11.5, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.trailing, 12)
        }
        .frame(minHeight: 18)
        .frame(minWidth: minimumWidth, alignment: .leading)
        .background(backgroundColor)
    }

    private var marker: String {
        switch line.change {
        case .removed: "−"
        case .added: "+"
        case .unchanged: " "
        }
    }

    private var markerColor: Color {
        switch line.change {
        case .removed: .red
        case .added: .green
        case .unchanged: .clear
        }
    }

    private var backgroundColor: Color {
        switch line.change {
        case .removed: Color.red.opacity(0.16)
        case .added: Color.green.opacity(0.16)
        case .unchanged: .clear
        }
    }
}
