import Foundation

/// A socket on a physical link that is sending at the rate of a live
/// stream, found before the tunnel takes the route. Moving it into the
/// tunnel changes the public address its receiver sees, so a protocol like
/// SRT or RTMP would reconnect once; kept on its link, it never notices.
struct ActiveStream: Equatable, Sendable {
    let process: String
    let pid: Int32
    /// "udp" or "tcp".
    let protocolName: String
    let localPort: UInt16
    /// The far end, when the socket is connected. An SRT socket usually is
    /// not; the helper then learns it from one captured packet.
    let remote: String?
    let interface: String
    let bytesPerSecond: Int

    var megabitsPerSecond: Double { Double(bytesPerSecond) * 8 / 1_000_000 }
    var description: String {
        String(format: "%@ is sending %.1f Mbit/s over %@", process, megabitsPerSecond, interface)
    }
}

enum ActiveStreams {
    /// Below this a socket is background chatter, not a stream.
    static let minimumBytesPerSecond = 40_000
    static let ownProcesses: Set<String> = ["VERZLink", "VERZ Link", "verz_udp_proxy", "verz-bond", "com.omaralabed.verzlink.classic.udp"]

    /// Samples the system's per-socket counters for one second.
    static func detect(physical: Set<String>) async -> [ActiveStream] {
        await Task.detached(priority: .userInitiated) { () -> [ActiveStream] in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
            // Two delta samples: the first is the lifetime total, the second
            // is one second of traffic.
            process.arguments = ["-d", "-x", "-l", "2", "-J", "interface,bytes_in,bytes_out", "-t", "external"]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do { try process.run() } catch { return [] }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return parse(String(decoding: data, as: UTF8.self), physical: physical)
        }.value
    }

    /// Reads the tool's output: a header per sample, then a line per process
    /// followed by an indented line per socket. Only the last sample counts.
    static func parse(_ output: String, physical: Set<String>) -> [ActiveStream] {
        let lines = output.components(separatedBy: "\n")
        let blocks = lines.split(whereSeparator: { $0.contains("bytes_in") && $0.contains("bytes_out") })
        guard blocks.count >= 2, let last = blocks.last else { return [] }
        var streams: [ActiveStream] = []
        var process = ""
        var pid: Int32 = 0
        for line in last where !line.isEmpty {
            if !line.hasPrefix(" ") {
                // "Google Chrome H.54078        7186        4093": the name may
                // hold spaces; the counters follow a run of spaces.
                let head = line.components(separatedBy: "  ").first ?? line
                if let dot = head.lastIndex(of: "."), let number = Int32(head[head.index(after: dot)...]) {
                    process = String(head[..<dot])
                    pid = number
                } else {
                    process = head
                    pid = 0
                }
                continue
            }
            let fields = line.split(whereSeparator: { $0 == " " }).map(String.init)
            guard fields.count >= 5, fields[0] == "udp4" || fields[0] == "tcp4" else { continue }
            let endpoints = fields[1].components(separatedBy: "<->")
            guard endpoints.count == 2, let localPort = port(of: endpoints[0]) else { continue }
            let interface = fields[2]
            guard physical.contains(interface), let bytesOut = Int(fields[4]),
                  bytesOut >= minimumBytesPerSecond, !isOwn(process) else { continue }
            streams.append(ActiveStream(process: process, pid: pid, protocolName: String(fields[0].dropLast()),
                                        localPort: localPort, remote: host(of: endpoints[1]),
                                        interface: interface, bytesPerSecond: bytesOut))
        }
        return streams.sorted { $0.bytesPerSecond > $1.bytesPerSecond }
    }

    /// The tool cuts names to 15 characters ("verz_udp_proxy-").
    private static func isOwn(_ process: String) -> Bool {
        ownProcesses.contains { own in own == process || process.hasPrefix(own) || (process.count >= 15 && own.hasPrefix(process)) }
    }

    private static func port(of endpoint: String) -> UInt16? {
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        return UInt16(endpoint[endpoint.index(after: colon)...])
    }

    private static func host(of endpoint: String) -> String? {
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        let host = String(endpoint[..<colon])
        return host == "*" ? nil : host
    }
}
