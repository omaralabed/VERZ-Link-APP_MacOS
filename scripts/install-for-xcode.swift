import AppKit
import Foundation

// A separate aggregate build target runs this AFTER the app dependency has
// finished signing. A failure fails the build, so Run cannot launch a stale app.
struct InstallFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
let fm = FileManager.default
let identifier = "com.omaralabed.verzlink.classic"
let destination = URL(fileURLWithPath: "/Applications/VERZ Link.app")
func fail(_ message: String) throws -> Never { throw InstallFailure(message: message) }

func run(_ executable: String, _ arguments: [String]) throws {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = arguments
    try task.run()
    task.waitUntilExit()
    guard task.terminationStatus == 0 else {
        try fail("\(URL(fileURLWithPath: executable).lastPathComponent) failed (\(task.terminationStatus)). Installation stopped.")
    }
}

func info(_ app: URL) throws -> [String: Any] {
    let data = try Data(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
    guard let values = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
          values["CFBundleIdentifier"] as? String == identifier else {
        try fail("Refusing to install or replace a different application: \(app.path)")
    }
    return values
}

func verify(_ app: URL) throws {
    _ = try info(app)
    try run("/usr/bin/codesign", ["--verify", "--deep", "--strict",
        "-R=anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"H7728UD4B3\"", app.path])
}

func quitRunningCopies() throws {
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: identifier)
    for app in apps where !app.isTerminated {
        guard app.terminate() else {
            try fail("Please quit VERZ Link, then Run again. The installed app was not replaced.")
        }
    }
    let deadline = Date().addingTimeInterval(20)
    while apps.contains(where: { !$0.isTerminated }) && Date() < deadline {
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    guard apps.allSatisfy({ $0.isTerminated }) else {
        try fail("VERZ Link is still disconnecting. Quit it, then Run again; no force-quit was performed.")
    }
}

func install(source: URL, project: URL, checkOnly: Bool) throws {
    guard source.resolvingSymlinksInPath() != destination.resolvingSymlinksInPath() else {
        try fail("The build product must remain in DerivedData, separate from /Applications.")
    }
    try verify(source)
    try run("/usr/bin/swift", [project.appendingPathComponent("scripts/verify-udp-signing.swift").path, source.path])
    let version = try info(source)["CFBundleVersion"] as? String ?? "unknown"
    if checkOnly {
        print("Validated build \(version). Check only: no app stopped or installed.")
        return
    }

    let lock = URL(fileURLWithPath: "/Applications/.verz-link-xcode-install.lock")
    do { try fm.createDirectory(at: lock, withIntermediateDirectories: false) }
    catch { try fail("Cannot acquire the /Applications install lock. Check folder permissions and whether another VERZ build is installing. \(error.localizedDescription)") }
    defer { try? fm.removeItem(at: lock) } // Only the empty lock created by this invocation.

    guard (try? destination.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true else {
        try fail("Refusing to replace an application symlink at \(destination.path)")
    }
    let hadPrevious = fm.fileExists(atPath: destination.path)
    if hadPrevious { try verify(destination) }

    let stage = URL(fileURLWithPath: "/Applications/.verz-link-install-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    var retainRecovery = false
    defer { if !retainRecovery { try? fm.removeItem(at: stage) } }
    let candidate = stage.appendingPathComponent("candidate.app")
    let previous = stage.appendingPathComponent("previous.app")
    try run("/usr/bin/ditto", ["--norsrc", source.path, candidate.path])
    try verify(candidate)

    if hadPrevious {
        let backups = project.appendingPathComponent(".build/xcode-run-backups", isDirectory: true)
        try fm.createDirectory(at: backups, withIntermediateDirectories: true)
        let backup = backups.appendingPathComponent("previous-\(UUID().uuidString).zip")
        try run("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "--keepParent", destination.path, backup.path])
        print("Previous installed app saved to \(backup.path)")
    }
    try quitRunningCopies()
    if hadPrevious { try fm.moveItem(at: destination, to: previous) }
    do {
        try fm.moveItem(at: candidate, to: destination)
        try verify(destination)
    } catch {
        do {
            if fm.fileExists(atPath: destination.path) {
                try fm.moveItem(at: destination, to: stage.appendingPathComponent("failed-candidate.app"))
            }
            if hadPrevious { try fm.moveItem(at: previous, to: destination) }
        } catch {
            retainRecovery = true
            try fail("Installation and automatic rollback failed. Recovery files retained at \(stage.path): \(error.localizedDescription)")
        }
        throw error
    }
    print("Installed signed build \(version) at \(destination.path). Xcode will launch this exact product.")
}

do {
    var args = Array(CommandLine.arguments.dropFirst())
    let checkOnly = args.first == "--check"
    if checkOnly { args.removeFirst() }
    guard args.count == 2 else { try fail("Usage: install-for-xcode.swift [--check] Built.app ProjectDirectory") }
    try install(source: URL(fileURLWithPath: args[0]), project: URL(fileURLWithPath: args[1]), checkOnly: checkOnly)
} catch {
    fputs("error: VERZ Xcode installation: \(error.localizedDescription)\n", stderr)
    exit(1)
}
