import AppKit
import DiffSearchVulnCore
import SwiftUI

struct FindingsView: View {
    @Environment(AppModel.self) private var model
    @State private var showCodexActivity = false

    var body: some View {
        Group {
            if let analysis = model.tournamentRun?.finalAnalysis {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        HStack(alignment: .firstTextBaseline) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Prove the finding")
                                    .font(.largeTitle.weight(.semibold))
                                Text("Reproduce the old vulnerability, verify the patch, then make Codex dynamically test the patched binary for a bypass.")
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            DynamicProofBadge(attempt: model.codexExploitAttempt)
                        }

                        DynamicCampaignControl(
                            analysis: analysis,
                            showCodexActivity: $showCodexActivity
                        )

                        ProofPipeline(
                            analysis: analysis,
                            attempt: model.codexExploitAttempt
                        )

                        SiblingImplementationSearchSection(analysis: analysis)

                        if let attempt = model.codexExploitAttempt {
                            DynamicProofResult(attempt: attempt)
                        }

                        DynamicResearchContext(analysis: analysis)
                    }
                    .padding(26)
                    .frame(maxWidth: 1_050, alignment: .leading)
                }
            } else if model.isLoadingTournament {
                ProgressView("Loading final analysis…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView(
                    "No Final Analysis",
                    systemImage: "shield.slash",
                    description: Text("Load a completed tournament containing a validated final analysis.")
                )
            }
        }
        .navigationTitle("Findings")
        .sheet(isPresented: $showCodexActivity) {
            if let session = model.codexActivitySession {
                CodexActivityView(session: session)
                    .environment(model)
            }
        }
    }
}

private struct DynamicCampaignControl: View {
    @Environment(AppModel.self) private var model
    let analysis: WorkerFinalAnalysis
    @Binding var showCodexActivity: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 15) {
                Image(systemName: "scope")
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 54, height: 54)
                    .background(.purple.gradient, in: RoundedRectangle(cornerRadius: 14))
                VStack(alignment: .leading, spacing: 6) {
                    Text("Local dynamic zero-day campaign")
                        .font(.title2.weight(.semibold))
                    Text("Codex receives the complete old/new decompilation, final analysis, every bypass hypothesis, and narrow execution tools for both binaries inside a disposable sandbox on this research Mac. It keeps testing evidence-backed inputs until it reproduces a bypass or records why each avenue is exhausted.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            HStack(alignment: .center, spacing: 12) {
                Text("The targets cannot read your user files, cannot use the network, and can write only inside the disposable campaign folder. Hashes are checked immediately before each execution.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                campaignButtons
            }

            HStack(spacing: 14) {
                DynamicBoundaryLabel(icon: "shippingbox", text: "Disposable host sandbox")
                DynamicBoundaryLabel(icon: "wifi.slash", text: "Network denied")
                DynamicBoundaryLabel(icon: "doc.on.doc", text: "Old + patched pair")
                DynamicBoundaryLabel(icon: "checkmark.seal", text: "Host-sealed audit")
            }
            .font(.caption)
        }
        .padding(20)
        .background(Color.purple.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
        .overlay {
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color.purple.opacity(0.22), lineWidth: 1)
        }
    }

    @ViewBuilder
    private var campaignButtons: some View {
        if model.isRunningCodexExploit {
            ProgressView()
                .controlSize(.small)
            Button("Show Live Tests") { showCodexActivity = true }
                .buttonStyle(.borderedProminent)
        } else {
            if model.codexActivitySession != nil {
                Button("Last Activity") { showCodexActivity = true }
            }
            Button("Start Dynamic Tests") { startResearch() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private func startResearch() {
        var researchTargets = analysis.bypassHypotheses
        if let siblingSearch = analysis.siblingImplementationSearch {
            let siblingTargets = (
                siblingSearch.sameFunctionCallSites + siblingSearch.similarImplementations
            ).filter { $0.risk != "equivalent_check" }.map {
                "Sibling path \($0.function) [\($0.risk)]: \($0.nextTest)"
            }
            researchTargets.append(contentsOf: siblingTargets)
            researchTargets.append(contentsOf: siblingSearch.unresolvedGaps.map {
                "Sibling-search coverage gap: \($0)"
            })
        }
        let hypotheses = researchTargets.enumerated().map { index, value in
            "\(index + 1). \(value)"
        }.joined(separator: "\n")
        model.askCodexToExploit(
            selectedHypothesis: "Systematically investigate every patch-bypass hypothesis, prioritizing the strongest evidence-derived avenue.\n\n\(hypotheses)",
            testInput: "Derive concrete inputs from the binary diff. Reproduce the vulnerable baseline on the old target, verify the same input is blocked by the patched target, then mutate the input and exercise other changed branches against the patched target.",
            expectedOutcome: "A finding is proven only when guest output records the old vulnerable baseline, the patched control, and a distinct bypass that succeeds against the patched version. Otherwise return the exact blocker or exhausted avenues.",
            labNotes: "This campaign was explicitly launched from Findings for authorized local bug-bounty research on this dedicated safe research Mac. Test only the staged pair through the contained host tools. Continue after individual failures, but never invent success.",
            executionMode: "host_dynamic"
        )
        showCodexActivity = model.codexActivitySession != nil
    }
}

private struct SiblingImplementationSearchSection: View {
    let analysis: WorkerFinalAnalysis

    var body: some View {
        GroupBox("Same-function and sibling implementation search") {
            VStack(alignment: .leading, spacing: 14) {
                if let search = analysis.siblingImplementationSearch {
                    HStack {
                        Label(
                            search.status.replacingOccurrences(of: "_", with: " ").uppercased(),
                            systemImage: search.status == "complete"
                                ? "checkmark.magnifyingglass"
                                : "exclamationmark.magnifyingglass"
                        )
                        .font(.caption.weight(.bold))
                        .foregroundStyle(search.status == "complete" ? Color.green : Color.orange)
                        Spacer()
                        Text("\(search.searchedFunctionIDs.count) patched function(s) searched")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Text("The patched export was scanned for every direct caller of the selected function and for other implementations sharing helpers, imports, strings, or semantic naming. These paths become dynamic test targets when protection is missing or uncertain.")
                        .font(.callout)
                        .foregroundStyle(.secondary)

                    SiblingFindingList(
                        title: "Same patched function used elsewhere",
                        emptyText: "No additional direct call sites were identified in the scanned export.",
                        findings: search.sameFunctionCallSites
                    )
                    SiblingFindingList(
                        title: "Similar implementations elsewhere",
                        emptyText: "No evidence-backed similar implementation was identified.",
                        findings: search.similarImplementations
                    )
                    if !search.coverageNotes.isEmpty {
                        FindingList(
                            title: "Observed coverage",
                            icon: "scope",
                            tint: .blue,
                            values: search.coverageNotes
                        )
                    }
                    if !search.unresolvedGaps.isEmpty {
                        FindingList(
                            title: "Unresolved coverage gaps",
                            icon: "exclamationmark.triangle",
                            tint: .orange,
                            values: search.unresolvedGaps
                        )
                    }
                } else {
                    Label("Legacy analysis — rerun the tournament to generate sibling-search evidence.", systemImage: "arrow.clockwise")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(8)
        }
    }
}

private struct SiblingFindingList: View {
    let title: String
    let emptyText: String
    let findings: [WorkerSiblingImplementationFinding]

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title)
                .font(.headline)
            if findings.isEmpty {
                Text(emptyText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(findings) { finding in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(finding.function)
                                .font(.callout.monospaced().weight(.medium))
                                .textSelection(.enabled)
                            Spacer()
                            Text(riskLabel(finding.risk))
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(riskColor(finding.risk))
                        }
                        Text(finding.relationship)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("OBSERVED: \(finding.evidence)")
                            .font(.callout)
                            .textSelection(.enabled)
                        if finding.risk != "equivalent_check" {
                            Text("NEXT TEST: \(finding.nextTest)")
                                .font(.caption)
                                .foregroundStyle(.orange)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(11)
                    .background(riskColor(finding.risk).opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
                }
            }
        }
    }

    private func riskLabel(_ risk: String) -> String {
        switch risk {
        case "equivalent_check": "EQUIVALENT CHECK"
        case "missing_check": "MISSING CHECK"
        default: "UNCERTAIN"
        }
    }

    private func riskColor(_ risk: String) -> Color {
        switch risk {
        case "equivalent_check": .green
        case "missing_check": .red
        default: .orange
        }
    }
}

private struct DynamicBoundaryLabel: View {
    let icon: String
    let text: String

    var body: some View {
        Label(text, systemImage: icon)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(.quaternary.opacity(0.6), in: Capsule())
    }
}

private struct ProofPipeline: View {
    let analysis: WorkerFinalAnalysis
    let attempt: WorkerCodexExploitAttempt?

    private var oldObserved: Bool {
        attempt?.result.testCases.contains {
            $0.status == "executed_old_binary" || $0.status == "bypass_reproduced_in_guest"
        } == true
    }

    private var patchObserved: Bool {
        attempt?.result.testCases.contains {
            $0.status == "executed_patched_binary" || $0.status == "bypass_reproduced_in_guest"
        } == true
    }

    private var bypassObserved: Bool {
        attempt?.result.verdict == "bypass_reproduced_in_guest"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Proof chain")
                .font(.title2.weight(.semibold))
            HStack(alignment: .top, spacing: 12) {
                ProofGate(
                    number: 1,
                    title: "Old version reproduced",
                    detail: oldObserved
                        ? "Guest output records the vulnerable baseline."
                        : concise(analysis.vulnerableBehavior),
                    complete: oldObserved
                )
                Image(systemName: "arrow.right")
                    .foregroundStyle(.tertiary)
                    .padding(.top, 47)
                ProofGate(
                    number: 2,
                    title: "Patch control verified",
                    detail: patchObserved
                        ? "The patched binary blocked the original input."
                        : concise(analysis.securityInvariant),
                    complete: patchObserved
                )
                Image(systemName: "arrow.right")
                    .foregroundStyle(.tertiary)
                    .padding(.top, 47)
                ProofGate(
                    number: 3,
                    title: "Bypass reproduced",
                    detail: bypassObserved
                        ? "A distinct input crossed the patched boundary in the guest."
                        : "No zero-day is proven until a patched-version bypass is observed.",
                    complete: bypassObserved
                )
            }
        }
    }

    private func concise(_ value: String) -> String {
        let compact = value.replacingOccurrences(of: "\n", with: " ")
        return compact.count > 145 ? String(compact.prefix(142)) + "…" : compact
    }
}

private struct ProofGate: View {
    let number: Int
    let title: String
    let detail: String
    let complete: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Text("\(number)")
                    .font(.caption.monospacedDigit().weight(.bold))
                    .frame(width: 25, height: 25)
                    .background(tint.opacity(0.15), in: Circle())
                    .foregroundStyle(tint)
                Spacer()
                Image(systemName: complete ? "checkmark.seal.fill" : "circle.dotted")
                    .foregroundStyle(tint)
            }
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(4)
            Text(complete ? "OBSERVED" : "NOT PROVEN")
                .font(.caption2.weight(.bold))
                .foregroundStyle(tint)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
        .background(tint.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }

    private var tint: Color { complete ? .green : .orange }
}

private struct DynamicProofResult: View {
    let attempt: WorkerCodexExploitAttempt

    var body: some View {
        GroupBox("Latest campaign") {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    ExploitVerdictBadge(verdict: attempt.result.verdict)
                    Text(attempt.mode == "host_dynamic"
                        ? "CONTAINED HOST TEST"
                        : (attempt.mode == "utm_dynamic" ? "DYNAMIC GUEST" : "EVIDENCE-ONLY"))
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Open Audit Folder") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: attempt.attemptDirectory))
                    }
                }
                Text(attempt.result.summary)
                    .font(.title3.weight(.medium))
                    .textSelection(.enabled)
                ForEach(attempt.result.testCases) { testCase in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(testCase.name).font(.headline)
                            Spacer()
                            Text(testCase.status.replacingOccurrences(of: "_", with: " ").uppercased())
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(testCase.status == "bypass_reproduced_in_guest" ? .red : .secondary)
                        }
                        Text(testCase.observedResult)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    .padding(11)
                    .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
                }
                if !attempt.result.limitations.isEmpty {
                    FindingList(
                        title: "Still not proven",
                        icon: "exclamationmark.triangle",
                        tint: .orange,
                        values: attempt.result.limitations
                    )
                }
            }
            .padding(8)
        }
    }
}

private struct DynamicResearchContext: View {
    let analysis: WorkerFinalAnalysis

    var body: some View {
        GroupBox("Research target sent to Codex") {
            VStack(alignment: .leading, spacing: 13) {
                FindingNarrative(
                    title: "Known vulnerable behavior",
                    icon: "exclamationmark.shield",
                    tint: .red,
                    text: analysis.vulnerableBehavior
                )
                FindingNarrative(
                    title: "Patched security boundary",
                    icon: "checkmark.shield",
                    tint: .green,
                    text: "\(analysis.patchExplanation)\n\nInvariant: \(analysis.securityInvariant)"
                )
                FindingList(
                    title: "Initial bypass hypotheses",
                    icon: "arrow.trianglehead.branch",
                    tint: .pink,
                    values: analysis.bypassHypotheses
                )
            }
            .padding(8)
        }
    }
}

private struct DynamicProofBadge: View {
    let attempt: WorkerCodexExploitAttempt?

    var body: some View {
        let proven = attempt?.result.verdict == "bypass_reproduced_in_guest"
        Label(proven ? "ZERO-DAY REPRODUCED" : "NOT YET PROVEN",
              systemImage: proven ? "checkmark.seal.fill" : "questionmark.diamond")
            .font(.caption.weight(.bold))
            .foregroundStyle(proven ? Color.red : Color.orange)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background((proven ? Color.red : Color.orange).opacity(0.12), in: Capsule())
    }
}

struct PatchFlowComparisonView: View {
    let analysis: WorkerFinalAnalysis

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            BehaviorFlowGraph(
                title: "Before · vulnerable flow",
                icon: "exclamationmark.triangle.fill",
                tint: .red,
                steps: [
                    BehaviorFlowStep(
                        title: "Untrusted input arrives",
                        detail: "Attacker-controlled data reaches the affected function."
                    ),
                    BehaviorFlowStep(
                        title: "Safeguard is missing",
                        detail: concise(analysis.vulnerableBehavior)
                    ),
                    BehaviorFlowStep(
                        title: "Sensitive operation continues",
                        detail: "Processing continues without the required security check."
                    ),
                    BehaviorFlowStep(
                        title: "Boundary can be crossed",
                        detail: "The vulnerable behavior can produce attacker-controlled impact."
                    )
                ]
            )
            BehaviorFlowGraph(
                title: "Now · patched flow",
                icon: "checkmark.shield.fill",
                tint: .green,
                steps: [
                    BehaviorFlowStep(
                        title: "Untrusted input arrives",
                        detail: "The same input first reaches the new patch gate."
                    ),
                    BehaviorFlowStep(
                        title: "Patch validates it",
                        detail: concise(analysis.patchExplanation)
                    ),
                    BehaviorFlowStep(
                        title: "Invariant is enforced",
                        detail: concise(analysis.securityInvariant)
                    ),
                    BehaviorFlowStep(
                        title: "Reject or continue safely",
                        detail: "Invalid input stops; accepted input proceeds past the gate."
                    )
                ]
            )
        }
    }

    private func concise(_ text: String) -> String {
        let compact = text.replacingOccurrences(of: "\n", with: " ")
        guard compact.count > 150 else { return compact }
        return String(compact.prefix(147)) + "…"
    }
}

struct BehaviorFlowStep {
    let title: String
    let detail: String
}

struct BehaviorFlowGraph: View {
    let title: String
    let icon: String
    let tint: Color
    let steps: [BehaviorFlowStep]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                Label(title, systemImage: icon)
                    .font(.headline)
                    .foregroundStyle(tint)
                    .padding(.bottom, 12)
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .top, spacing: 10) {
                        Text("\(index + 1)")
                            .font(.caption.monospacedDigit().weight(.bold))
                            .foregroundStyle(tint)
                            .frame(width: 26, height: 26)
                            .background(tint.opacity(0.14), in: Circle())
                        VStack(alignment: .leading, spacing: 3) {
                            Text(step.title)
                                .font(.callout.weight(.semibold))
                            Text(step.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(3)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(10)
                    .background(tint.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
                    if index + 1 < steps.count {
                        Image(systemName: "arrow.down")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(tint.opacity(0.75))
                            .frame(width: 46, height: 24)
                    }
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }
}

struct FindingNarrative: View {
    let title: String
    let icon: String
    let tint: Color
    let text: String

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Label(title, systemImage: icon)
                    .font(.headline)
                    .foregroundStyle(tint)
                Text(text)
                    .textSelection(.enabled)
                    .lineSpacing(3)
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct FindingList: View {
    let title: String
    let icon: String
    let tint: Color
    let values: [String]

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label(title, systemImage: icon)
                    .font(.headline)
                    .foregroundStyle(tint)
                ForEach(Array(values.enumerated()), id: \.offset) { _, value in
                    HStack(alignment: .top, spacing: 10) {
                        Circle()
                            .fill(tint)
                            .frame(width: 6, height: 6)
                            .padding(.top, 7)
                        Text(value)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
