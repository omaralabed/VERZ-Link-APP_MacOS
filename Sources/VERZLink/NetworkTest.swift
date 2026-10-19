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

enum NetworkTestError: LocalizedError, Equatable {
    case latencyUnavailable
    case protectedServiceUnavailable
    case invalidLatencyResponse
    case invalidServiceResponse
    case downloadIntegrity
    case uploadIntegrity

    var errorDescription: String? {
        switch self {
        case .latencyUnavailable:
            "The latency check could not be completed. Check your connection and try again."
        case .protectedServiceUnavailable:
            "The protected diagnostics service is temporarily unavailable. Please try again."
        case .invalidLatencyResponse:
            "The latency check returned an unexpected response."
        case .invalidServiceResponse:
            "The diagnostics service returned an unexpected response."
        case .downloadIntegrity:
            "The downloaded test file did not pass its integrity check."
        case .uploadIntegrity:
            "The uploaded test file did not pass its integrity check."
        }
    }
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

    static func userFacingMessage(for error: Error) -> String {
        if let error = error as? NetworkTestError {
            return error.localizedDescription
        }
        return "Diagnostics could not complete. Check your VERZ connection and try again."
    }

    private func command(_ executable: String, _ arguments: [String],
                         failure: NetworkTestError) async throws -> Data {
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
                    do { try process.run() } catch { active = nil; lock.unlock(); throw failure }
                    lock.unlock()
                    let data = stdout.fileHandleForReading.readDataToEndOfFile()
                    _ = stderr.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    lock.lock(); active = nil; let stopped = cancelled; lock.unlock()
                    if stopped { throw CancellationError() }
                    guard process.terminationStatus == 0 else {
                        throw failure
                    }
                    continuation.resume(returning: data)
                } catch is CancellationError {
                    continuation.resume(throwing: CancellationError())
                } catch {
                    continuation.resume(throwing: (error as? NetworkTestError) ?? failure)
                }
            }
        }
    }

    private func curl(_ path: String, extra: [String] = []) async throws -> Data {
        try await command("/usr/bin/curl", ["--fail", "--silent", "--show-error", "--noproxy", "*",
            "--connect-timeout", "8", "--max-time", "60"] + extra + ["http://\(serverIP):8080/\(path)"],
            failure: .protectedServiceUnavailable)
    }

    func run(uploadFile: URL, serverIP: String, progress: @escaping @Sendable (Double, String) -> Void) async throws -> TestResult {
        self.serverIP = serverIP
        progress(0.05, "Measuring latency · 10 real pings")
        let pingData = try await command("/sbin/ping", ["-c", "10", "-W", "1500", serverIP],
                                         failure: .latencyUnavailable)
        let ping = String(decoding: pingData, as: UTF8.self)
        guard let summary = ping.components(separatedBy: .newlines).first(where: { $0.contains("round-trip") }),
              let valuesText = summary.components(separatedBy: " = ").last else {
            throw NetworkTestError.invalidLatencyResponse
        }
        let values = valuesText.components(separatedBy: "/").prefix(3).compactMap(Double.init)
        let lossExpression = try NSRegularExpression(pattern: "([0-9.]+)% packet loss")
        let nsPing = ping as NSString
        guard values.count == 3,
              let match = lossExpression.firstMatch(in: ping, range: NSRange(location: 0, length: nsPing.length)),
              let loss = Double(nsPing.substring(with: match.range(at: 1))) else {
            throw NetworkTestError.invalidLatencyResponse
        }
        progress(0.35, "Checking the server through the tunnel")
        let health = try await curl("health")
        guard String(decoding: health, as: UTF8.self) == "VERZ real TCP over encrypted IP tunnel\n" else {
            throw NetworkTestError.invalidServiceResponse
        }
        progress(0.5, "Downloading a real file")
        var started = Date()
        let download = try await curl("download")
        let downSeconds = Date().timeIntervalSince(started)
        let downHash = SHA256.hash(data: download).map { String(format: "%02x", $0) }.joined()
        let expectedData = try await curl("sha256")
        let expected = String(decoding: expectedData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard downHash == expected else { throw NetworkTestError.downloadIntegrity }
        progress(0.75, "Uploading a real file and verifying its checksum")
        let upload = try Data(contentsOf: uploadFile)
        let upHash = SHA256.hash(data: upload).map { String(format: "%02x", $0) }.joined()
        started = Date()
        let response = try await curl("upload", extra: ["--data-binary", "@\(uploadFile.path)"])
        let upSeconds = Date().timeIntervalSince(started)
        guard String(decoding: response, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == upHash else {
            throw NetworkTestError.uploadIntegrity
        }
        progress(1, "Both file checksums verified")
        return TestResult(date: Date(), lossPercent: loss, minimumMs: values[0], averageMs: values[1], maximumMs: values[2],
            downloadBytes: download.count, downloadMbps: Double(download.count) * 8 / max(downSeconds, 0.000001) / 1_000_000,
            downloadHash: downHash, uploadBytes: upload.count, uploadMbps: Double(upload.count) * 8 / max(upSeconds, 0.000001) / 1_000_000,
            uploadHash: upHash)
    }
}
