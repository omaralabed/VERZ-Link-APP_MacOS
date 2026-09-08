import SwiftUI
import AppKit

@main
struct VERZLinkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = LinkModel()

    var body: some Scene {
        WindowGroup("VERZ Link", id: "main") {
            ContentView(model: model)
                .frame(minWidth: 940, minHeight: 680)
                .preferredColorScheme(.dark)
                .onAppear { delegate.model = model }
        }
        .defaultSize(width: 1100, height: 780)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Connection") {
                Button(model.busy ? "Disconnect" : "Connect") {
                    model.busy ? model.disconnect() : model.connect()
                }.keyboardShortcut("k", modifiers: [.command])
                Button("Run diagnostics") { model.runTest() }.disabled(!model.canTest)
                Divider()
                Button("Import connection profile…") { model.importKey() }.disabled(model.busy)
                Button("Export private connection profile…") { model.exportProfile() }.disabled(!model.hasCredential)
            }
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: LinkModel?
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model, model.busy else { return .terminateNow }
        model.whenDisconnected = { sender.reply(toApplicationShouldTerminate: true) }
        model.disconnect()
        return .terminateLater
    }
}
