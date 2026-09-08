import Foundation
import Darwin

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
    private var listener: Int32 = -1
    private var connection: Int32 = -1
    private var cancelled = false
    private var process: Process?
    private var source: DispatchSourceRead?
    private var configuration: Data
    private let callback: @Sendable (EngineEvent) -> Void

    init(secret: Data, relay: String, interfaces: [String], policy: String, configuration: Data,
         callback: @escaping @Sendable (EngineEvent) -> Void) throws {
        self.callback = callback
        self.configuration = configuration
        directory = URL(fileURLWithPath: "/tmp/verz-link-app-\(UUID().uuidString)", isDirectory: true)
        engineURL = directory.appendingPathComponent("verz-bond")
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: false,
                                    attributes: [.posixPermissions: 0o700])
        do {
            for name in ["verz-bond", "verz-app-helper"] {
                guard let binary = Bundle.main.url(forResource: name, withExtension: nil) else {
                    throw LinkError.message("The app is missing its Rust engine. Rebuild VERZ Link.")
                }
                let staged = directory.appendingPathComponent(name)
                try manager.copyItem(at: binary, to: staged)
                try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: staged.path)
            }
            let secretURL = directory.appendingPathComponent("lab-secret")
            try secret.write(to: secretURL, options: .atomic)
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretURL.path)
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
        guard let script = Bundle.main.url(forResource: "StartTunnel", withExtension: "applescript") else {
            throw LinkError.message("The app is missing its administrator launcher.")
        }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        child.arguments = [script.path, directory.path, String(getuid()), relay, interfaces.joined(separator: ","), policy]
        let output = Pipe()
        child.standardOutput = output
        child.standardError = output
        process = child
        try child.run()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let data = output.fileHandleForReading.readDataToEndOfFile()
            child.waitUntilExit()
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            lock.lock(); let wasCancelled = cancelled; lock.unlock()
            if child.terminationStatus != 0 && !wasCancelled {
                callback(EngineEvent(event: "launch_error", line: text, code: Int(child.terminationStatus)))
            }
            finish()
            callback(EngineEvent(event: "session_ended", code: Int(child.terminationStatus)))
        }
    }

    func updateConfiguration(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, data != configuration else { return }
        configuration = data
        sendConfigurationLocked()
    }

    private func sendConfigurationLocked() {
        guard connection >= 0 else { return }
        let message = configuration + Data([10])
        _ = message.withUnsafeBytes { Darwin.write(connection, $0.baseAddress, $0.count) }
    }

    func disconnect() {
        lock.lock()
        cancelled = true
        if connection >= 0 {
            let command = Array("disconnect\n".utf8)
            _ = command.withUnsafeBytes { Darwin.write(connection, $0.baseAddress, $0.count) }
            _ = Darwin.shutdown(connection, SHUT_WR)
        } else {
            // Remove the listener before cancelling authorization. A late
            // administrator approval cannot start a tunnel without this app.
            source?.cancel(); source = nil; listener = -1
            if let process, process.isRunning { process.terminate() }
        }
        lock.unlock()
    }

    private func finish() {
        lock.lock()
        cancelled = true
        source?.cancel(); source = nil; listener = -1
        if connection >= 0 { _ = Darwin.shutdown(connection, SHUT_RDWR) }
        lock.unlock()
        // This directory was created exclusively by this session and contains
        // only staged executable copies, the temporary key, and its socket.
        try? FileManager.default.removeItem(at: directory)
    }
}
