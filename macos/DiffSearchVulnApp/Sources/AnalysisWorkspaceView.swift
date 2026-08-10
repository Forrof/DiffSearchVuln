import AppKit
import SwiftUI

struct AnalysisWorkspaceView: View {
    @Environment(AppModel.self) private var model
    @State private var isAddingAnalysis = false

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            analysisBar
            Divider()
            if model.selectedAnalysis != nil {
                Picker("View", selection: $model.analysisTab) {
                    ForEach(AnalysisTab.allCases) { tab in
                        Label(tab.title, systemImage: tab.icon)
                            .tag(tab)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 820)
                .padding(.horizontal, 18)
                .padding(.vertical, 10)

                Divider()
                Group {
                    switch model.analysisTab {
                    case .summary:
                        AnalysisSummaryView()
                    case .diff:
                        CandidateBrowserView()
                    case .tournament:
                        TournamentView()
                    case .findings:
                        FindingsView()
                    case .exploitLab:
                        ExploitLabView()
                    }
                }
            } else {
                ContentUnavailableView {
                    Label("No Analyses", systemImage: "square.stack.3d.up.slash")
                } description: {
                    Text("Create an analysis to keep its binary provenance, function diff, tournament, and findings together.")
                } actions: {
                    Button("New Analysis…") { isAddingAnalysis = true }
                        .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(model.selectedAnalysis?.title ?? "Analyses")
        .sheet(isPresented: $isAddingAnalysis) {
            NewAnalysisSheet()
                .environment(model)
        }
    }

    private var analysisBar: some View {
        HStack(spacing: 12) {
            Text("Analysis")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Picker(
                "Analysis",
                selection: Binding(
                    get: { model.selectedAnalysisID },
                    set: { model.selectAnalysis($0) }
                )
            ) {
                ForEach(model.analysisCases) { analysis in
                    Text(analysis.title)
                        .tag(Optional(analysis.id))
                }
            }
            .labelsHidden()
            .frame(minWidth: 260, idealWidth: 350, maxWidth: 460)
            Button {
                isAddingAnalysis = true
            } label: {
                Label("New Analysis", systemImage: "plus")
            }
            Spacer()
            if let analysis = model.selectedAnalysis {
                Text("\(analysis.oldVersion) → \(analysis.newVersion)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
    }
}

struct AnalysisSummaryView: View {
    @Environment(AppModel.self) private var model

    private let columns = [
        GridItem(.adaptive(minimum: 210, maximum: 320), spacing: 14)
    ]

    var body: some View {
        if let analysis = model.selectedAnalysis {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    VStack(alignment: .leading, spacing: 9) {
                        Text(analysis.title)
                            .font(.largeTitle.weight(.semibold))
                        Text(analysis.provenanceSentence)
                            .font(.title3)
                            .foregroundStyle(.secondary)
                            .lineSpacing(3)
                            .frame(maxWidth: 850, alignment: .leading)
                        if let url = URL(string: analysis.sourceURL), !analysis.sourceURL.isEmpty {
                            Link(destination: url) {
                                Label(analysis.sourceURL, systemImage: "arrow.up.right.square")
                            }
                            .font(.callout)
                        }
                    }

                    LazyVGrid(columns: columns, alignment: .leading, spacing: 14) {
                        AnalysisSummaryMetric(
                            title: "Binary",
                            value: analysis.binaryDescription,
                            icon: "apple.terminal"
                        )
                        AnalysisSummaryMetric(
                            title: "Versions",
                            value: "\(analysis.oldVersion) → \(analysis.newVersion)",
                            icon: "arrow.left.arrow.right"
                        )
                        AnalysisSummaryMetric(
                            title: "Changed functions",
                            value: model.candidatePage.map { $0.totalCount.formatted() } ?? "Not loaded",
                            icon: "function"
                        )
                        AnalysisSummaryMetric(
                            title: "Finding",
                            value: findingSummary,
                            icon: "shield.lefthalf.filled"
                        )
                    }

                    GroupBox("Analysis inputs") {
                        VStack(alignment: .leading, spacing: 12) {
                            AnalysisPathRow(
                                title: "Semantic diff",
                                path: analysis.diffDirectory,
                                icon: "point.3.connected.trianglepath.dotted"
                            )
                            Divider()
                            AnalysisPathRow(
                                title: "Tournament run",
                                path: analysis.tournamentRunDirectory,
                                icon: "arrow.triangle.branch"
                            )
                        }
                        .padding(8)
                    }

                    HStack {
                        Button("Open Function Diff") { model.analysisTab = .diff }
                            .buttonStyle(.borderedProminent)
                        Button("Open Findings") { model.analysisTab = .findings }
                            .disabled(model.tournamentRun?.finalAnalysis == nil)
                    }
                }
                .padding(26)
                .frame(maxWidth: 1_080, alignment: .leading)
            }
        }
    }

    private var findingSummary: String {
        guard let final = model.tournamentRun?.finalAnalysis else { return "Not analyzed" }
        let state = final.findingState.replacingOccurrences(of: "_", with: " ")
        return "\(state.capitalized) · \(final.confidence.formatted(.percent.precision(.fractionLength(0))))"
    }
}

struct AnalysisSummaryMetric: View {
    let title: String
    let value: String
    let icon: String

    var body: some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 34)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(value)
                        .font(.headline)
                        .lineLimit(2)
                }
                Spacer(minLength: 0)
            }
            .padding(7)
        }
    }
}

struct AnalysisPathRow: View {
    let title: String
    let path: String?
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(Color.accentColor)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.headline)
                Text(path ?? "Not attached")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
            Spacer()
        }
    }
}

struct NewAnalysisSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var productName = ""
    @State private var oldVersion = ""
    @State private var newVersion = ""
    @State private var binaryDescription = "macOS Apple Silicon Mach-O binary"
    @State private var sourceDescription = "the vendor's official release archive"
    @State private var sourceURL = ""
    @State private var diffDirectory = ""
    @State private var tournamentDirectory = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("New Analysis")
                    .font(.title2.weight(.semibold))
                Spacer()
            }
            .padding(20)
            Divider()
            Form {
                Section("Release pair") {
                    TextField("Product", text: $productName)
                    HStack {
                        TextField("Previous version", text: $oldVersion)
                        TextField("Updated version", text: $newVersion)
                    }
                    TextField("Binary description", text: $binaryDescription)
                }
                Section("Acquisition") {
                    TextField("Where the releases came from", text: $sourceDescription)
                    TextField("Source URL", text: $sourceURL)
                }
                Section("Completed local artifacts") {
                    PathSettingRow(
                        title: "Semantic diff directory",
                        value: $diffDirectory,
                        choose: { chooseDirectory(title: "Choose Completed Semantic Diff") }
                    )
                    PathSettingRow(
                        title: "Tournament run directory",
                        value: $tournamentDirectory,
                        choose: { chooseDirectory(title: "Choose Tournament Run") }
                    )
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
                Button("Create Analysis") {
                    model.addAnalysis(
                        title: "\(productName) \(oldVersion) → \(newVersion)",
                        productName: productName,
                        oldVersion: oldVersion,
                        newVersion: newVersion,
                        binaryDescription: binaryDescription,
                        sourceDescription: sourceDescription,
                        sourceURL: sourceURL,
                        diffDirectory: diffDirectory,
                        tournamentRunDirectory: tournamentDirectory
                    )
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!isValid)
            }
            .padding(16)
        }
        .frame(width: 700, height: 570)
    }

    private var isValid: Bool {
        [productName, oldVersion, newVersion, binaryDescription, sourceDescription]
            .allSatisfy { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    private func chooseDirectory(title: String) -> String? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url?.path : nil
    }
}
