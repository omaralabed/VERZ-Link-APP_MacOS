// Functional handover check, not a speed benchmark. Run while disconnected,
// then click Connect during the run. Each lane requests one byte repeatedly.
// The persistent lane reuses its session; fresh creates a session per request.
// URLSession uses the current macOS proxy settings. Metrics show whether a
// request actually used a proxy; success alone is not evidence of proxy use.
// Usage: swift scripts/check-mac-handover.swift [iterations, default 80]
import Foundation

final class Metrics: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let label: String
    init(_ label: String) { self.label = label }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didFinishCollecting metrics: URLSessionTaskMetrics) {
        for metric in metrics.transactionMetrics {
            print("metrics \(label) proxy=\(metric.isProxyConnection) reused=\(metric.isReusedConnection) protocol=\(metric.networkProtocolName ?? "unknown") localPort=\(metric.localPort?.description ?? "unknown")")
        }
    }
}

func makeSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.timeoutIntervalForRequest = 4
    config.timeoutIntervalForResource = 5
    return URLSession(configuration: config)
}

func runLane(_ name: String, count: Int, fresh: Bool) async -> Int {
    let persistent = makeSession()
    defer { persistent.invalidateAndCancel() }
    var failures = 0
    var slowest = 0.0
    for index in 0..<count {
        let session = fresh ? makeSession() : persistent
        let started = Date()
        do {
            let url = URL(string: "https://speed.cloudflare.com/__down?bytes=1&handover=\(name)-\(index)")!
            let (data, response) = try await session.data(from: url, delegate: Metrics("\(name)-\(index)"))
            let elapsed = Date().timeIntervalSince(started)
            slowest = max(slowest, elapsed)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status != 200 || data.count != 1 { failures += 1 }
            print("request \(name)-\(index) status=\(status) bytes=\(data.count) seconds=\(String(format: "%.3f", elapsed))")
        } catch {
            failures += 1
            print("request \(name)-\(index) ERROR \(error.localizedDescription)")
        }
        if fresh { session.invalidateAndCancel() }
        try? await Task.sleep(nanoseconds: 500_000_000)
    }
    print("SUMMARY \(name) requests=\(count) failures=\(failures) slowestSuccessSeconds=\(String(format: "%.3f", slowest))")
    return failures
}

let count = max(1, min(240, CommandLine.arguments.dropFirst().first.flatMap(Int.init) ?? 80))
Task {
    async let persistent = runLane("persistent", count: count, fresh: false)
    async let fresh = runLane("fresh", count: count, fresh: true)
    let failures = await (persistent, fresh)
    exit(failures.0 + failures.1 == 0 ? 0 : 1)
}
dispatchMain()
