import AppKit
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var repositoryRoot = ""
    @State private var pythonExecutable = ""
    @State private var databasePath = ""
    @State private var vaultRoot = ""
    @State private var analysisRoot = ""

    var body: some View {
        Form {
            Section("Worker") {
                PathSettingRow(
                    title: "Repository",
                    value: $repositoryRoot,
                    choose: { chooseDirectory(title: "Choose DiffSearchVuln Repository") }
                )
                PathSettingRow(
                    title: "Python 3.12",
                    value: $pythonExecutable,
                    choose: { chooseFile(title: "Choose Python 3.12") }
                )
                PathSettingRow(
                    title: "Database",
                    value: $databasePath,
                    choose: { chooseSavePath(title: "Choose Metadata Database") }
                )
            }
            Section("Large storage") {
                PathSettingRow(
                    title: "Artifact vault",
                    value: $vaultRoot,
                    choose: { chooseDirectory(title: "Choose Artifact Vault") }
                )
                PathSettingRow(
                    title: "Analysis cache",
                    value: $analysisRoot,
                    choose: { chooseDirectory(title: "Choose Analysis Cache") }
                )
                Text("The vault and Ghidra/cache roots are independent so either can live on the external SSD. Missing volumes will pause jobs rather than silently falling back to the internal disk.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                HStack {
                    ConnectionBadge(state: model.connectionState)
                    Spacer()
                    Button("Save and Reconnect") {
                        model.saveSettings(
                            repositoryRoot: repositoryRoot,
                            pythonExecutable: pythonExecutable,
                            databasePath: databasePath,
                            vaultRoot: vaultRoot,
                            analysisRoot: analysisRoot
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled([repositoryRoot, pythonExecutable, databasePath, vaultRoot, analysisRoot].contains { $0.isEmpty })
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .padding(.top, 8)
        .onAppear {
            repositoryRoot = model.repositoryRoot
            pythonExecutable = model.pythonExecutable
            databasePath = model.databasePath
            vaultRoot = model.vaultRoot
            analysisRoot = model.analysisRoot
        }
    }

    private func chooseDirectory(title: String) -> String? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url?.path : nil
    }

    private func chooseFile(title: String) -> String? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url?.path : nil
    }

    private func chooseSavePath(title: String) -> String? {
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = "state.sqlite3"
        return panel.runModal() == .OK ? panel.url?.path : nil
    }
}

struct PathSettingRow: View {
    let title: String
    @Binding var value: String
    let choose: () -> String?

    var body: some View {
        HStack {
            TextField(title, text: $value)
                .textFieldStyle(.roundedBorder)
            Button("Choose…") {
                if let selected = choose() {
                    value = selected
                }
            }
        }
    }
}
