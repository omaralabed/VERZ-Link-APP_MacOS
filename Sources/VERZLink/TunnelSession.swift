import Foundation
import Darwin
import ServiceManagement
import Security

@objc(VERZSessionServiceProtocol)
protocol VERZSessionServiceProtocol {
    func start(directory: String, relay: String, interfaces: [String], policy: String,
               withReply reply: @escaping (Int32, String) -> Void)
}

enum ConnectionHelper {
    static let name = "com.verz.link.session-service"
    static var service: SMAppService { .daemon(plistName: "\(name).plist") }
    static func signingTeam() throws -> String {
        var code: SecCode?; var staticCode: SecStaticCode?; var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dictionary = info as? [String: Any],
              let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty else {
            throw LinkError.message("Select your Apple Developer Team in Xcode and rebuild. The connection helper requires a signed app.")
        }
        return team
    }
    static func ensureReady() throws {
        _ = try signingTeam()
        if service.status == .notRegistered || service.status == .notFound {
            do { try service.register() }
            catch { if service.status != .requiresApproval { throw error } }
        }
        guard service.status == .enabled else {
            SMAppService.openSystemSettingsLoginItems()
            throw LinkError.message("One-time setup: enable VERZ Link in System Settings → General → Login Items & Extensions, then Connect again. Normal connections do not request an administrator password.")
        }
    }
}

struct EngineEvent: Decodable, Sendable {
    let event: String
    var line: String?
    var code: Int?
}

enum LinkError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}

/// The app owns the control socket. Losing this socket tells the privileged
/// Rust supervisor to stop its child, including when the app crashes or quits.
final class TunnelSession: @unchecked Sendable {
    let directory: URL
    let engineURL: URL
    private let lock = NSLock()
    private let controlQueue = DispatchQueue(label: "com.verz.link.control", qos: .userInitiated)
    private var listener: Int32 = -1
    private var connection: Int32 = -1
    private var cancelled = false
    private var serviceConnection: NSXPCConnection?
    private var completed = false
    private var source: DispatchSourceRead?
    private var configuration: Data
    private let callback: @Sendable (EngineEvent) -> Void

    init(secret: Data, relay: String, interfaces: [String], policy: String, configuration: Data,
         callback: @escaping @Sendable (EngineEvent) -> Void) throws {
        self.callback = callback
        self.configuration = configuration
        try ConnectionHelper.ensureReady()
        directory = URL(fileURLWithPath: "/tmp/verz-link-app-\(UUID().uuidString)", isDirectory: true)
        engineURL = directory.appendingPathComponent("verz-bond")
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        do {
            for name in ["verz-bond"] {
                guard let binary = Bundle.main.url(forResource: name, withExtension: nil) else {
                    throw LinkError.message("The app is missing its Rust engine. Rebuild VERZ Link.")
                }
                let staged = directory.appendingPathComponent(name)
                try manager.copyItem(at: binary, to: staged)
                try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: staged.path)
            }
            if !secret.isEmpty {
                let secretURL = directory.appendingPathComponent("lab-secret")
                try secret.write(to: secretURL, options: .atomic)
                try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretURL.path)
            }
            try createListener()
            try launch(relay: relay, interfaces: interfaces, policy: policy)
        } catch {
            if let source { source.cancel(); self.source = nil; listener = -1 }
            else if listener >= 0 { Darwin.close(listener); listener = -1 }
            try? manager.removeItem(at: directory)
            throw error
        }
    }

    private func createListener() throws {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw LinkError.message("Could not create app control socket.") }
        listener = fd
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        let bytes = Array(directory.appendingPathComponent("app.sock").path.utf8) + [0]
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw LinkError.message("Control socket path is too long.")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes)
        }
        let status = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard status == 0, Darwin.listen(fd, 1) == 0 else {
            throw LinkError.message("Could not listen for the Rust engine.")
        }
        _ = chmod(directory.appendingPathComponent("app.sock").path, 0o600)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .global(qos: .userInitiated))
        source.setEventHandler { [weak self] in self?.acceptEngine() }
        source.setCancelHandler { Darwin.close(fd) }
        self.source = source
        source.resume()
    }

    private func acceptEngine() {
        lock.lock()
        guard !cancelled, listener >= 0 else { lock.unlock(); return }
        let accepted = Darwin.accept(listener, nil, nil)
        guard accepted >= 0 else { lock.unlock(); return }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(accepted, &uid, &gid) == 0, uid == 0 else {
            Darwin.close(accepted); lock.unlock(); return
        }
        if connection >= 0 { Darwin.close(accepted); lock.unlock(); return }
        connection = accepted
        var flag: Int32 = 1
        _ = setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout<Int32>.size))
        // A wedged supervisor must not hold our state lock indefinitely.
        var timeout = timeval(tv_sec: 0, tv_usec: 250_000)
        _ = setsockopt(accepted, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = fcntl(accepted, F_SETFL, 0)
        _ = fcntl(accepted, F_SETFD, FD_CLOEXEC)
        sendConfigurationLocked()
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            var pending = Data()
            var buffer = [UInt8](repeating: 0, count: 8192)
            while true {
                let count = Darwin.read(accepted, &buffer, buffer.count)
                if count <= 0 { break }
                pending.append(contentsOf: buffer.prefix(count))
                if pending.count > 65536 { break }
                while let newline = pending.firstIndex(of: 10) {
                    let line = pending[..<newline]
                    if let event = try? JSONDecoder().decode(EngineEvent.self, from: Data(line)) {
                        callback(event)
                    }
                    pending.removeSubrange(...newline)
                }
            }
            lock.lock()
            if connection == accepted { connection = -1 }
            Darwin.close(accepted)
            lock.unlock()
        }
    }

    private func launch(relay: String, interfaces: [String], policy: String) throws {
        let team = try ConnectionHelper.signingTeam()
        let connection = NSXPCConnection(machServiceName: ConnectionHelper.name, options: .privileged)
        connection.setCodeSigningRequirement("anchor apple generic and identifier \"com.verz.link.session-service\" and certificate leaf[subject.OU] = \"\(team)\"")
        connection.remoteObjectInterface = NSXPCInterface(with: VERZSessionServiceProtocol.self)
        connection.invalidationHandler = { [weak self] in self?.sessionEnded(1, "The macOS connection helper is unavailable. Check its approval in System Settings.") }
        serviceConnection = connection
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.sessionEnded(1, error.localizedDescription)
        } as! VERZSessionServiceProtocol
        proxy.start(directory: directory.path, relay: relay, interfaces: interfaces, policy: policy) { [weak self] code, text in
            self?.sessionEnded(code, text)
        }
    }

    private func sessionEnded(_ code: Int32, _ text: String) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let wasCancelled = cancelled
        lock.unlock()
        if code != 0 && !wasCancelled { callback(EngineEvent(event: "launch_error", line: text, code: Int(code))) }
        finish()
        callback(EngineEvent(event: "session_ended", code: Int(code)))
    }

    func updateConfiguration(_ data: Data) {
        controlQueue.async { [self] in
            lock.lock(); defer { lock.unlock() }
            guard !cancelled, data != configuration else { return }
            configuration = data
            sendConfigurationLocked()
        }
    }

    private func sendConfigurationLocked() {
        guard connection >= 0 else { return }
        let message = configuration + Data([10])
        if !Self.writeCommand(message, to: connection) {
            callback(EngineEvent(event: "engine_error", line: "The local tunnel controller stopped responding. Closing this session to restore networking."))
            _ = Darwin.shutdown(connection, SHUT_RDWR)
        }
    }

    // SOCK_STREAM writes may be partial. Called only on a background queue,
    // with a socket send timeout; never from the SwiftUI main actor.
    static func writeCommand(_ message: Data, to fd: Int32) -> Bool {
        message.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
    }

    func disconnect() {
        controlQueue.async { [self] in disconnectInBackground() }
    }

    private func disconnectInBackground() {
        var invalidate: NSXPCConnection?
        lock.lock()
        cancelled = true
        if connection >= 0 {
            _ = Self.writeCommand(Data("disconnect\n".utf8), to: connection)
            _ = Darwin.shutdown(connection, SHUT_WR)
        } else {
            // A delayed service request cannot start a tunnel without the
            // authenticated local app socket.
            source?.cancel(); source = nil; listener = -1
            invalidate = serviceConnection
        }
        lock.unlock()
        invalidate?.invalidate()
    }

    private func finish() {
        lock.lock()
        cancelled = true
        source?.cancel(); source = nil; listener = -1
        if connection >= 0 { _ = Darwin.shutdown(connection, SHUT_RDWR) }
        let invalidate = serviceConnection; serviceConnection = nil
        lock.unlock()
        invalidate?.invalidate()
        // This directory was created exclusively by this session and contains
        // only staged executable copies, the temporary key, and its socket.
        try? FileManager.default.removeItem(at: directory)
    }
}
