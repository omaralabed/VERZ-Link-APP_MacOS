import Foundation

/// Versioned cumulative payload counters. Times belong to the producer's
/// monotonic clock, not UI callback arrival time.
struct PayloadTelemetry: Decodable {
    let version: Int
    let sourceId: String
    let sampledAtMs: UInt64
    let uploadBytes: UInt64
    let downloadBytes: UInt64
    let unmeasuredPackets: UInt64
    let basis: String
}

struct PayloadRateTracker {
    private var source: String?
    private var retired = Set<String>()
    private var points: [PayloadTelemetry] = []
    private var receivedAt: TimeInterval?
    private(set) var uploaded: UInt64 = 0
    private(set) var downloaded: UInt64 = 0
    private(set) var incompleteTotals = false
    private var invalidCounters = false
    var partial: Bool {
        invalidCounters || (points.count > 1 && points.last!.unmeasuredPackets > points.first!.unmeasuredPackets)
    }
    var hasSample: Bool { !points.isEmpty }

    mutating func receive(_ report: PayloadTelemetry, at arrival: TimeInterval) {
        guard report.version == 1, !report.sourceId.isEmpty, !retired.contains(report.sourceId),
              ["tcp_acknowledged_udp_datagrams", "tcp_socket_payload", "udp_datagrams"].contains(report.basis) else { return }
        if source != report.sourceId {
            if let source { retired.insert(source) }
            // A single app session should not have unbounded producer restarts.
            guard retired.count <= 64 else { invalidCounters = true; incompleteTotals = true; return }
            source = report.sourceId; points = []; invalidCounters = false
        }
        if let previous = points.last {
            guard report.sampledAtMs > previous.sampledAtMs else { return }
            guard report.uploadBytes >= previous.uploadBytes, report.downloadBytes >= previous.downloadBytes else {
                invalidCounters = true; incompleteTotals = true; return // same-epoch counter reset is not new traffic
            }
            uploaded += report.uploadBytes - previous.uploadBytes
            downloaded += report.downloadBytes - previous.downloadBytes
            if report.sampledAtMs - previous.sampledAtMs > 4_000 { points = [] }
        } else {
            // Totals include startup traffic, but no rate until a second real sample.
            uploaded += report.uploadBytes; downloaded += report.downloadBytes
        }
        incompleteTotals = incompleteTotals || report.unmeasuredPackets > 0
        points.append(report); receivedAt = arrival
        while points.count > 2 && report.sampledAtMs - points[1].sampledAtMs >= 3_000 { points.removeFirst() }
        // At most a few 500-ms reports normally. Bound anomalously fast producers too.
        if points.count > 128 { points.removeFirst(points.count - 128) }
    }

    func rate(at now: TimeInterval) -> (up: Double, down: Double)? {
        guard let receivedAt, now >= receivedAt, now - receivedAt < 3,
              points.count >= 2, let first = points.first, let last = points.last,
              last.sampledAtMs > first.sampledAtMs else { return nil }
        let seconds = Double(last.sampledAtMs - first.sampledAtMs) / 1_000
        return (Double(last.uploadBytes - first.uploadBytes) * 8 / seconds / 1_000_000,
                Double(last.downloadBytes - first.downloadBytes) * 8 / seconds / 1_000_000)
    }
}

struct PayloadTraffic {
    enum Source { case tunnel, direct, udp }
    private var tunnel = PayloadRateTracker()
    private var direct = PayloadRateTracker()
    private var udp = PayloadRateTracker()

    mutating func receive(_ report: PayloadTelemetry, from source: Source, at now: TimeInterval) {
        switch source {
        case .tunnel: tunnel.receive(report, at: now)
        case .direct: direct.receive(report, at: now)
        case .udp: udp.receive(report, at: now)
        }
    }

    struct Summary {
        let totalsReady: Bool
        let uploaded: UInt64
        let downloaded: UInt64
        let up: Double?
        let down: Double?
        let partial: Bool
        let incompleteTotals: Bool
    }
    func summary(mode: TransportMode, at now: TimeInterval) -> Summary {
        // Hybrid direct counters exclude relayed sockets. The tunnel observes
        // those plus non-proxy TCP, so none is counted at both boundaries.
        let sources = mode == .secure ? [tunnel, udp] : mode == .hybrid ? [tunnel, direct, udp] : [direct]
        let rates = sources.compactMap { $0.rate(at: now) }
        let fresh = rates.count == sources.count
        return Summary(totalsReady: sources.allSatisfy { $0.hasSample },
                       uploaded: sources.reduce(0) { $0 + $1.uploaded },
                       downloaded: sources.reduce(0) { $0 + $1.downloaded },
                       up: fresh ? rates.reduce(0) { $0 + $1.up } : nil,
                       down: fresh ? rates.reduce(0) { $0 + $1.down } : nil,
                       partial: sources.contains { $0.partial },
                       incompleteTotals: sources.contains { $0.incompleteTotals })
    }
}
