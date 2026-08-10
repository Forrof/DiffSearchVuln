import SwiftUI

@main
struct DiffSearchVulnApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            AppShellView()
                .environment(model)
                .frame(minWidth: 1_050, minHeight: 680)
                .task {
                    model.connectIfNeeded()
                }
        }
        .defaultSize(width: 1_280, height: 820)
        .commands {
            CommandGroup(after: .sidebar) {
                Button("Refresh") {
                    model.refreshCurrentSection()
                }
                .keyboardShortcut("r", modifiers: .command)
            }
        }

        Settings {
            SettingsView()
                .environment(model)
                .frame(width: 720, height: 470)
        }
    }
}
