import SwiftUI

struct ProgramIntelligenceView: View {
    @Environment(AppModel.self) private var model
    @State private var isPresentingNewProgram = false
    @State private var isConfirmingDeletion = false

    var body: some View {
        @Bindable var model = model
        HSplitView {
            VStack(spacing: 0) {
                List(selection: $model.selectedBountyProgramID) {
                    ForEach(model.bountyPrograms) { program in
                        ProgramRow(program: program)
                            .tag(program.id)
                    }
                }
                .frame(minWidth: 270, idealWidth: 310)

                Divider()
                HStack {
                    Button {
                        isPresentingNewProgram = true
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                    Button(role: .destructive) {
                        isConfirmingDeletion = true
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                    .disabled(model.selectedBountyProgramID == nil)
                    Spacer()
                }
                .padding(10)
            }

            Group {
                if let identifier = model.selectedBountyProgramID,
                   let binding = programBinding(identifier: identifier) {
                    ProgramRecordEditor(program: binding)
                } else {
                    ContentUnavailableView {
                        Label("No Program Selected", systemImage: "checkmark.shield")
                    } description: {
                        Text("Add a bounty program and record its current authorization, scope, tooling, disclosure, and local-testing rules before analysis.")
                    } actions: {
                        Button("Add Program") {
                            isPresentingNewProgram = true
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
            .frame(minWidth: 620, maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("Program Intelligence")
        .sheet(isPresented: $isPresentingNewProgram) {
            NewProgramSheet(isPresented: $isPresentingNewProgram)
                .environment(model)
        }
        .confirmationDialog(
            "Delete this local program record?",
            isPresented: $isConfirmingDeletion,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                model.removeSelectedBountyProgram()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes only the local planning record. It does not change anything on Bugcrowd.")
        }
    }

    private func programBinding(identifier: String) -> Binding<BountyProgramRecord>? {
        guard let initial = model.bountyPrograms.first(where: { $0.id == identifier }) else {
            return nil
        }
        return Binding(
            get: {
                model.bountyPrograms.first(where: { $0.id == identifier }) ?? initial
            },
            set: { updated in
                model.replaceBountyProgram(updated)
            }
        )
    }
}

private struct ProgramRow: View {
    let program: BountyProgramRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(program.name)
                .font(.headline)
                .lineLimit(1)
            Text(program.targetName.isEmpty ? program.access.rawValue : program.targetName)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Label(program.gateStatus.rawValue, systemImage: program.gateStatus.icon)
                .font(.caption.weight(.medium))
                .foregroundStyle(program.gateStatus.color)
        }
        .padding(.vertical, 4)
    }
}

private struct ProgramRecordEditor: View {
    @Binding var program: BountyProgramRecord

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 5) {
                        TextField("Program name", text: $program.name)
                            .textFieldStyle(.plain)
                            .font(.largeTitle.weight(.semibold))
                        Text("Local-only selection record. No program data is included in the public repository.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    ProgramGateBadge(status: program.gateStatus)
                }

                GroupBox("Program and target") {
                    Form {
                        TextField("Platform", text: $program.platform)
                        TextField("Program URL", text: $program.programURL)
                        TextField("In-scope target", text: $program.targetName)
                        TextField("Maximum P1 reward", text: $program.maximumP1Reward)
                        TextField("Maximum P2 reward", text: $program.maximumP2Reward)
                        Picker("Access", selection: $program.access) {
                            ForEach(BountyProgramAccess.allCases) { option in
                                Text(option.rawValue).tag(option)
                            }
                        }
                        Picker("Lifecycle", selection: $program.lifecycle) {
                            ForEach(BountyProgramLifecycle.allCases) { option in
                                Text(option.rawValue).tag(option)
                            }
                        }
                    }
                    .formStyle(.grouped)
                }

                GroupBox("Authorization and reputation gates") {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle("Paid rewards", isOn: $program.isPaid)
                        Toggle("High/Critical product findings are eligible", isOn: $program.highCriticalInScope)
                        Toggle("The target can be tested entirely in an authorized local environment", isOn: $program.localTestingAllowed)
                        Toggle("Official adjacent releases are available", isOn: $program.adjacentReleasesAvailable)
                        Toggle("Complete current scope and rules reviewed", isOn: $program.scopeReviewed)
                        DatePicker(
                            "Scope reviewed on",
                            selection: $program.scopeReviewedAt,
                            displayedComponents: [.date]
                        )
                        .disabled(!program.scopeReviewed)
                        Toggle("Bugcrowd identity verification complete", isOn: $program.identityVerified)
                        Toggle("Prior or active report conflict", isOn: $program.priorReportConflict)
                            .tint(.red)
                        Picker("Diff-tool policy", selection: $program.toolingPolicy) {
                            ForEach(BountyToolingPolicy.allCases) { option in
                                Text(option.rawValue).tag(option)
                            }
                        }
                        Picker("Disclosure", selection: $program.disclosurePolicy) {
                            ForEach(BountyDisclosurePolicy.allCases) { option in
                                Text(option.rawValue).tag(option)
                            }
                        }
                    }
                    .padding(8)
                }

                GroupBox {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: program.gateStatus.icon)
                            .font(.title2)
                            .foregroundStyle(program.gateStatus.color)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Automatic decision: \(program.gateStatus.rawValue)")
                                .font(.headline)
                            Text(program.gateExplanation)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(8)
                }

                GroupBox("Notes") {
                    TextEditor(text: $program.notes)
                        .font(.body.monospaced())
                        .frame(minHeight: 110)
                        .padding(5)
                }

                GroupBox("Submission-quality gate") {
                    VStack(alignment: .leading, spacing: 9) {
                        QualityGateRow(text: "Re-read the live brief and target exclusions immediately before testing and submission.")
                        QualityGateRow(text: "Confirm the tested build is the current release and preserve official artifact hashes.")
                        QualityGateRow(text: "Search advisories, CVEs, changelogs, issues, and prior reports for duplicates.")
                        QualityGateRow(text: "Prove the root cause with negative controls; do not infer it from the payload alone.")
                        QualityGateRow(text: "Replicate the impact from a clean local environment and keep exact transcripts.")
                        QualityGateRow(text: "Claim High/Critical severity only when the demonstrated attack path supports it.")
                        QualityGateRow(text: "Keep private-program and nondisclosure evidence out of the public repository.")
                    }
                    .padding(8)
                }
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
        }
    }
}

private struct ProgramGateBadge: View {
    let status: ProgramGateStatus

    var body: some View {
        Label(status.rawValue, systemImage: status.icon)
            .font(.callout.weight(.semibold))
            .foregroundStyle(status.color)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(status.color.opacity(0.12), in: Capsule())
    }
}

private struct QualityGateRow: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "checkmark.circle")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct NewProgramSheet: View {
    @Environment(AppModel.self) private var model
    @Binding var isPresented: Bool
    @State private var name = ""
    @State private var programURL = ""
    @State private var targetName = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Add Program")
                .font(.title2.weight(.semibold))
            Text("Only a local planning record is created. No account or program data is added to the repository.")
                .foregroundStyle(.secondary)
            Form {
                TextField("Program name", text: $name)
                TextField("Program URL", text: $programURL)
                TextField("Initial target", text: $targetName)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) {
                    isPresented = false
                }
                Button("Add") {
                    model.addBountyProgram(
                        name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                        programURL: programURL.trimmingCharacters(in: .whitespacesAndNewlines),
                        targetName: targetName.trimmingCharacters(in: .whitespacesAndNewlines)
                    )
                    isPresented = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 500)
    }
}

private extension ProgramGateStatus {
    var color: Color {
        switch self {
        case .eligible: .green
        case .reviewRequired: .yellow
        case .blocked: .orange
        case .excluded: .red
        }
    }

    var icon: String {
        switch self {
        case .eligible: "checkmark.shield.fill"
        case .reviewRequired: "exclamationmark.triangle.fill"
        case .blocked: "lock.fill"
        case .excluded: "xmark.octagon.fill"
        }
    }
}
