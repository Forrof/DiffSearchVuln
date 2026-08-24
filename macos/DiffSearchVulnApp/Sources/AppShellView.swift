import SwiftUI

struct AppShellView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                Section("Workspace") {
                    sidebarItem(.analyses)
                    sidebarItem(.products)
                    sidebarItem(.programs)
                }
                Section {
                    sidebarItem(.settings)
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 215)
        } detail: {
            Group {
                switch model.selection {
                case .analyses:
                    AnalysisWorkspaceView()
                case .products:
                    ProductsView()
                case .programs:
                    ProgramIntelligenceView()
                case .settings:
                    SettingsView()
                }
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    ConnectionBadge(state: model.connectionState)
                }
            }
        }
        .alert(
            "DiffSearchVuln",
            isPresented: Binding(
                get: { model.presentedError != nil },
                set: { if !$0 { model.presentedError = nil } }
            )
        ) {
            Button("OK", role: .cancel) {
                model.presentedError = nil
            }
        } message: {
            Text(model.presentedError ?? "Unknown error")
        }
    }

    private func sidebarItem(_ section: AppSection) -> some View {
        Label(section.title, systemImage: section.icon)
            .tag(section)
    }
}

struct ConnectionBadge: View {
    let state: WorkerConnectionState

    private var color: Color {
        switch state {
        case .connected: .green
        case .connecting: .orange
        case .failed: .red
        case .disconnected: .secondary
        }
    }

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(state.label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(.regularMaterial, in: Capsule())
    }
}

struct PlaceholderWorkflowView: View {
    let title: String
    let icon: String
    let detail: String

    var body: some View {
        ContentUnavailableView(title, systemImage: icon, description: Text(detail))
            .navigationTitle(title)
    }
}
