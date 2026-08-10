import AppKit
import DiffSearchVulnCore
import SwiftUI

struct TournamentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if let run = model.tournamentRun {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        runHeader(run)
                        metrics(run)
                        finalists(run)
                        if let analysis = run.finalAnalysis {
                            GroupBox("Adjudicator result") {
                                VStack(alignment: .leading, spacing: 12) {
                                    HStack {
                                        FindingStateBadge(state: analysis.findingState)
                                        Text(analysis.confidence, format: .percent.precision(.fractionLength(0)))
                                            .font(.headline.monospacedDigit())
                                        Spacer()
                                    }
                                    Text(analysis.patchExplanation)
                                        .textSelection(.enabled)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(8)
                            }
                        }
                    }
                    .padding(26)
                    .frame(maxWidth: 1_050, alignment: .leading)
                }
            } else if model.isLoadingTournament {
                ProgressView("Validating tournament audit trail…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView {
                    Label("No Tournament Selected", systemImage: "arrow.triangle.branch")
                } description: {
                    Text("Choose a completed tournament run to inspect its finalists and final adjudication.")
                } actions: {
                    Button("Choose Run…") { chooseRun() }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .navigationTitle("Tournament")
        .toolbar {
            Button("Choose Run…") { chooseRun() }
        }
    }

    private func runHeader(_ run: WorkerTournamentRun) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Two-pass candidate tournament")
                    .font(.largeTitle.weight(.semibold))
                Spacer()
                StatusBadge(status: run.status)
            }
            Text("Model \(run.model) · \(run.runKey.prefix(16))…")
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
        }
    }

    private func metrics(_ run: WorkerTournamentRun) -> some View {
        HStack(spacing: 14) {
            TournamentMetric(title: "Pilot pool", value: "\(run.poolCount)")
            TournamentMetric(title: "Judged groups", value: "\(run.groupCount)")
            TournamentMetric(title: "Codex calls", value: "\(run.codexCallCount)")
            TournamentMetric(title: "Finalists", value: "\(run.finalistIDs.count)")
        }
    }

    private func finalists(_ run: WorkerTournamentRun) -> some View {
        GroupBox("Final two") {
            VStack(spacing: 0) {
                ForEach(Array(run.finalistIDs.enumerated()), id: \.element) { index, identifier in
                    HStack(spacing: 14) {
                        Text("\(index + 1)")
                            .font(.headline.monospacedDigit())
                            .frame(width: 32, height: 32)
                            .background(Color.accentColor.opacity(0.14), in: Circle())
                            .foregroundStyle(Color.accentColor)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(FunctionNameDisplay.compact(model.candidateName(for: identifier)))
                                .font(.system(.body, design: .monospaced).weight(.medium))
                                .help(model.candidateName(for: identifier))
                            Text(identifier)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(12)
                    if index + 1 < run.finalistIDs.count { Divider() }
                }
            }
        }
    }

    private func chooseRun() {
        let panel = NSOpenPanel()
        panel.title = "Choose Tournament Run"
        panel.prompt = "Choose"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            model.loadTournament(directory: url)
        }
    }
}

struct TournamentMetric: View {
    let title: String
    let value: String

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.title2.monospacedDigit().weight(.semibold))
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct StatusBadge: View {
    let status: String

    var body: some View {
        Label(status.capitalized, systemImage: status == "completed" ? "checkmark.circle.fill" : "clock")
            .font(.caption.weight(.medium))
            .foregroundStyle(status == "completed" ? .green : .orange)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(.quaternary, in: Capsule())
    }
}

struct FindingStateBadge: View {
    let state: String

    var body: some View {
        Text(state.replacingOccurrences(of: "_", with: " ").uppercased())
            .font(.caption2.weight(.bold))
            .foregroundStyle(state == "likely_patch" ? .green : .orange)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                (state == "likely_patch" ? Color.green : Color.orange).opacity(0.13),
                in: Capsule()
            )
    }
}
