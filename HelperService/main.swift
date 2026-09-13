import Foundation
import Security
import Darwin

@objc(VERZSessionServiceProtocol)
protocol VERZSessionServiceProtocol {
    func start(directory: String, relay: String, interfaces: [String], policy: String,
               withReply reply: @escaping (Int32, String) -> Void)
}

let serviceName = "com.omaralabed.verzlink.classic.session-service"
var executableBuffer = [CChar](repeating: 0, count: 4096)
guard proc_pidpath(getpid(), &executableBuffer, UInt32(executableBuffer.count)) > 0 else { exit(1) }
let executable = URL(fileURLWithPath: String(cString: executableBuffer)).resolvingSymlinksInPath()
let resources = executable.deletingLastPathComponent()
let appURL = resources.deletingLastPathComponent().deletingLastPathComponent()

func signingTeam() throws -> String {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(appURL as CFURL, [], &code) == errSecSuccess,
          let code, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
        throw NSError(domain: serviceName, code: 1, userInfo: [NSLocalizedDescriptionKey: "The installed app signature is invalid"])
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dictionary = info as? [String: Any],
          let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
          !team.isEmpty, team.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
        throw NSError(domain: serviceName, code: 2, userInfo: [NSLocalizedDescriptionKey: "An Apple-signed development or distribution identity is required"])
    }
    return team
}

func verifyExecutable(_ url: URL, identifier: String, team: String) throws {
    var code: SecStaticCode?; var requirement: SecRequirement?
    let text = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
          SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
          SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
        throw NSError(domain: serviceName, code: 4, userInfo: [NSLocalizedDescriptionKey: "The bundled networking executable is not signed by this app's team"])
    }
}

final class Sessions {
    static let shared = Sessions()
    private let lock = NSLock()
    private var users = Set<uid_t>()
    func claim(_ uid: uid_t) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard users.count < 16 else { return false }
        return users.insert(uid).inserted
    }
    func release(_ uid: uid_t) {
        lock.lock()
        users.remove(uid)
        let idle = users.isEmpty
        lock.unlock()
        guard idle else { return }
        // A launchd Mach service does not need to remain resident between VERZ
        // sessions. Exiting after the reply prevents an in-place Xcode rebuild
        // from leaving a stale signed process behind; launchd starts the
        // current bundled executable on the next connection.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let stillIdle = self.users.isEmpty
            self.lock.unlock()
            if stillIdle { exit(0) }
        }
    }
}

final class Controller: NSObject, VERZSessionServiceProtocol {
    let uid: uid_t
    let team: String
    init(uid: uid_t, team: String) { self.uid = uid; self.team = team }
    func start(directory: String, relay: String, interfaces: [String], policy: String,
               withReply reply: @escaping (Int32, String) -> Void) {
        let prefix = "/tmp/verz-link-app-"
        var metadata = stat()
        guard uid >= 501, directory.hasPrefix(prefix),
              UUID(uuidString: String(directory.dropFirst(prefix.count))) != nil,
              lstat(directory, &metadata) == 0, metadata.st_uid == uid,
              metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_mode & 0o077 == 0,
              !interfaces.isEmpty, interfaces.count <= 256,
              interfaces.allSatisfy({ !$0.isEmpty && $0.utf8.count < 16 && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) } }),
              ["smart", "performance", "continuity", "data-saver"].contains(policy),
              Sessions.shared.claim(uid) else {
            reply(1, "Invalid session request or this user already has a running session"); return
        }
        // Freeze and verify copies in a fresh root-only directory. Checking a
        // user-writable bundle then executing from it has a replacement race.
        let trusted = URL(fileURLWithPath: "/private/tmp/verz-trusted-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: trusted, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for (name, identifier) in [("verz-app-helper", "com.verz.link.helper"), ("verz-bond", "com.verz.link.engine")] {
                let destination = trusted.appendingPathComponent(name)
                try FileManager.default.copyItem(at: resources.appendingPathComponent(name), to: destination)
                try verifyExecutable(destination, identifier: identifier, team: team)
            }
        } catch {
            try? FileManager.default.removeItem(at: trusted)
            Sessions.shared.release(uid); reply(1, error.localizedDescription); return
        }
        let child = Process()
        child.executableURL = trusted.appendingPathComponent("verz-app-helper")
        child.arguments = [directory, String(uid), relay, interfaces.joined(separator: ","), policy]
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let output = Pipe(); child.standardOutput = output; child.standardError = output
        child.standardInput = FileHandle.nullDevice
        do { try child.run() }
        catch { try? FileManager.default.removeItem(at: trusted); Sessions.shared.release(uid); reply(1, error.localizedDescription); return }
        DispatchQueue.global(qos: .userInitiated).async { [uid] in
            let data = output.fileHandleForReading.readDataToEndOfFile()
            child.waitUntilExit()
            try? FileManager.default.removeItem(at: trusted)
            Sessions.shared.release(uid)
            reply(child.terminationStatus, String(decoding: data.suffix(8192), as: UTF8.self))
        }
    }
}

final class Delegate: NSObject, NSXPCListenerDelegate {
    let requirement: String
    let team: String
    init(team: String) {
        self.team = team
        self.requirement = "anchor apple generic and identifier \"com.omaralabed.verzlink.classic\" and certificate leaf[subject.OU] = \"\(team)\""
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier >= 501 else { return false }
        // launchd validates the audit token against this requirement; no PID
        // lookup or trust in a caller-provided UID/path is used for identity.
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: VERZSessionServiceProtocol.self)
        connection.exportedObject = Controller(uid: connection.effectiveUserIdentifier, team: team)
        connection.resume()
        return true
    }
}

do {
    if CommandLine.arguments.contains("--verify-package") {
        let team = try signingTeam()
        try verifyExecutable(resources.appendingPathComponent("verz-bond"), identifier: "com.verz.link.engine", team: team)
        try verifyExecutable(resources.appendingPathComponent("verz-app-helper"), identifier: "com.verz.link.helper", team: team)
        print("Signed VERZ app and Rust executables verified")
        exit(0)
    }
    guard geteuid() == 0 else { throw NSError(domain: serviceName, code: 3) }
    let delegate = Delegate(team: try signingTeam())
    let listener = NSXPCListener(machServiceName: serviceName)
    listener.delegate = delegate
    listener.resume()
    withExtendedLifetime(delegate) { dispatchMain() }
} catch {
    NSLog("VERZ session service failed: %@ (app: %@)", error.localizedDescription, appURL.path)
    fputs("VERZ session service: \(error.localizedDescription)\n", stderr)
    exit(1)
}
