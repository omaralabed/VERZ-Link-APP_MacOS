import Foundation
import CryptoKit

struct TestResult: Codable, Sendable {
    var date: Date
    var lossPercent: Double
    var minimumMs: Double
    var averageMs: Double
    var maximumMs: Double
    var downloadBytes: Int
    var downloadMbps: Double
    var downloadHash: String
    var uploadBytes: Int
    var uploadMbps: Double
    var uploadHash: String
}

final class NetworkTest: @unchecked Sendable {
    private let lock = NSLock()
    private var active: Process?
    private var cancelled = false
    private var serverIP = "10.78.0.1"

    func cancel() {
        lock.lock(); cancelled = true
        if let active, active.isRunning { active.terminate() }
        lock.unlock()
    }

    private func command(_ executable: String, _ arguments: [String]) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                do {
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: executable)
                    process.arguments = arguments
                    let stdout = Pipe(), stderr = Pipe()
                    process.standardOutput = stdout; process.standardError = stderr
                    lock.lock()
                    if cancelled { lock.unlock(); throw CancellationError() }
                    active = process
                    do { try process.run() } catch { active = nil; lock.unlock(); throw error }
                    lock.unlock()
                    let data = stdout.fileHandleForReading.readDataToEndOfFile()
                    let errors = stderr.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    lock.lock(); active = nil; let stopped = cancelled; lock.unlock()
                    if stopped { throw CancellationError() }
                    guard process.terminationStatus == 0 else {
                        throw LinkError.message(String(decoding: errors + data, as: UTF8.self))
                    }
                    continuation.resume(returning: data)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func curl(_ path: String, extra: [String] = []) async throws -> Data {
        try await command("/usr/bin/curl", ["--fail", "--silent", "--show-error", "--noproxy", "*",
            "--connect-timeout", "8", "--max-time", "60"] + extra + ["http://\(serverIP):8080/\(path)"])
    }

    func run(uploadFile: URL, serverIP: String, progress: @escaping @Sendable (Double, String) -> Void) async throws -> TestResult {
        self.serverIP = serverIP
        progress(0.05, "Measuring latency · 10 real pings")
        let pingData = try await command("/sbin/ping", ["-c", "10", "-W", "1500", serverIP])
        let ping = String(decoding: pingData, as: UTF8.self)
        guard let summary = ping.components(separatedBy: .newlines).first(where: { $0.contains("round-trip") }),
              let valuesText = summary.components(separatedBy: " = ").last else {
            throw LinkError.message("The server did not return usable ping results.")
        }
        let values = valuesText.components(separatedBy: "/").prefix(3).compactMap(Double.init)
        let lossExpression = try NSRegularExpression(pattern: "([0-9.]+)% packet loss")
        let nsPing = ping as NSString
        guard values.count == 3,
              let match = lossExpression.firstMatch(in: ping, range: NSRange(location: 0, length: nsPing.length)),
              let loss = Double(nsPing.substring(with: match.range(at: 1))) else {
            throw LinkError.message("Unable to parse the ping measurement.")
        }
        progress(0.35, "Checking the server through the tunnel")
        let health = try await curl("health")
        guard String(decoding: health, as: UTF8.self) == "VERZ real TCP over encrypted IP tunnel\n" else {
            throw LinkError.message("Unexpected response from the private tunnel endpoint.")
        }
        progress(0.5, "Downloading a real file")
        var started = Date()
        let download = try await curl("download")
        let downSeconds = Date().timeIntervalSince(started)
        let downHash = SHA256.hash(data: download).map { String(format: "%02x", $0) }.joined()
        let expectedData = try await curl("sha256")
        let expected = String(decoding: expectedData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard downHash == expected else { throw LinkError.message("Downloaded file failed its integrity check.") }
        progress(0.75, "Uploading a real file and verifying its checksum")
        let upload = try Data(contentsOf: uploadFile)
        let upHash = SHA256.hash(data: upload).map { String(format: "%02x", $0) }.joined()
        started = Date()
        let response = try await curl("upload", extra: ["--data-binary", "@\(uploadFile.path)"])
        let upSeconds = Date().timeIntervalSince(started)
        guard String(decoding: response, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == upHash else {
            throw LinkError.message("Uploaded file failed its integrity check on the server.")
        }
        progress(1, "Both file checksums verified")
        return TestResult(date: Date(), lossPercent: loss, minimumMs: values[0], averageMs: values[1], maximumMs: values[2],
            downloadBytes: download.count, downloadMbps: Double(download.count) * 8 / max(downSeconds, 0.000001) / 1_000_000,
            downloadHash: downHash, uploadBytes: upload.count, uploadMbps: Double(upload.count) * 8 / max(upSeconds, 0.000001) / 1_000_000,
            uploadHash: upHash)
    }
}
