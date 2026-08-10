import SwiftUI

struct OverviewView: View {
    @Environment(AppModel.self) private var model

    private let columns = [
        GridItem(.adaptive(minimum: 250, maximum: 340), spacing: 16)
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Patch intelligence, from shipped binaries")
                        .font(.largeTitle.weight(.semibold))
                    Text("Compare adjacent releases, localize security changes, and preserve every decision and piece of evidence.")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: 760, alignment: .leading)
                }

                LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
                    DashboardCard(
                        title: "Analysis worker",
                        value: model.connectionState.label,
                        icon: "bolt.horizontal.circle",
                        tint: connectionTint
                    )
                    DashboardCard(
                        title: "Configured products",
                        value: "\(model.products.count)",
                        icon: "shippingbox",
                        tint: .blue
                    )
                    DashboardCard(
                        title: "Candidate catalog",
                        value: model.candidatePage.map { "\($0.totalCount.formatted()) functions" } ?? "Not loaded",
                        icon: "point.3.connected.trianglepath.dotted",
                        tint: .purple
                    )
                    DashboardCard(
                        title: "Metadata store",
                        value: model.storeSchemaVersion.map { "Schema \($0)" } ?? "Waiting",
                        icon: "cylinder.split.1x2",
                        tint: .teal
                    )
                }

                GroupBox {
                    HStack(alignment: .center, spacing: 18) {
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 32))
                            .foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("rclone acceptance case")
                                .font(.headline)
                            Text("The validated 1.74.3 → 1.74.4 path-traversal diff is available locally with 54,190 preserved candidates.")
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Open Candidates") {
                            model.useAcceptanceFixture()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.acceptanceFixtureAvailable || !isConnected)
                    }
                    .padding(8)
                }

                VStack(alignment: .leading, spacing: 12) {
                    Text("Workflow")
                        .font(.title2.weight(.semibold))
                    HStack(spacing: 0) {
                        WorkflowStep(number: 1, title: "Import", detail: "Old and new releases")
                        WorkflowConnector()
                        WorkflowStep(number: 2, title: "Diff", detail: "Changed functions")
                        WorkflowConnector()
                        WorkflowStep(number: 3, title: "Tournament", detail: "Two passes, top two")
                        WorkflowConnector()
                        WorkflowStep(number: 4, title: "Analyze", detail: "Patch and bypasses")
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 1_100, alignment: .leading)
        }
        .navigationTitle("Overview")
    }

    private var isConnected: Bool {
        if case .connected = model.connectionState { return true }
        return false
    }

    private var connectionTint: Color {
        switch model.connectionState {
        case .connected: .green
        case .connecting: .orange
        case .failed: .red
        case .disconnected: .gray
        }
    }
}

struct DashboardCard: View {
    let title: String
    let value: String
    let icon: String
    let tint: Color

    var body: some View {
        GroupBox {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 24))
                    .foregroundStyle(tint)
                    .frame(width: 42, height: 42)
                    .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(value)
                        .font(.headline)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(7)
        }
    }
}

struct WorkflowStep: View {
    let number: Int
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 7) {
            Text("\(number)")
                .font(.headline)
                .frame(width: 32, height: 32)
                .background(Color.accentColor.opacity(0.14), in: Circle())
                .foregroundStyle(Color.accentColor)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct WorkflowConnector: View {
    var body: some View {
        Rectangle()
            .fill(.quaternary)
            .frame(width: 48, height: 1)
            .offset(y: -20)
    }
}
