import AppKit
import Foundation
import Darwin

struct ConnectionProfile: Codable {
    let version: Int
    let relay: String
    let key: String
}

struct TrafficSample: Identifiable {
    let id = UUID()
    let received: Double
    let sent: Double
}

struct ActivityEntry: Identifiable {
    let id = UUID()
    let date = Date()
    let message: String
}

enum ConnectionState: String {
    case disconnected = "Disconnected", authorizing = "Starting connection service"
    case connecting = "Connecting", connected = "Connected", reconnecting = "Waiting for networks", disconnecting = "Disconnecting"
}

enum TransportMode: String, CaseIterable, Identifiable {
    case direct, hybrid, secure
    var id: String { rawValue }
    var title: String {
        switch self {
        case .direct: "Direct Smart"
        case .hybrid: "Automatic Hybrid"
        case .secure: "Secure Continuity"
        }
    }
    var badge: String {
        switch self {
        case .direct: "DIRECT SMART"
        case .hybrid: "AUTOMATIC HYBRID"
        case .secure: "SECURE LINK"
        }
    }
}

/// The supported customer outcomes. Internal transport and scheduling
/// details are deliberately not exposed as a combinatorial settings matrix.
enum ConnectionPreset: String, CaseIterable, Identifiable {
    case bonded, smart, continuity, direct
    var id: String { rawValue }
    var title: String {
        switch self {
        case .bonded: "Bonded"
        case .smart: "Smart Repair"
        case .continuity: "Maximum Continuity"
        case .direct: "Direct, no server"
        }
    }
    var settings: (mode: TransportMode, policy: String) {
        switch self {
        case .bonded: (.secure, "performance")
        case .smart: (.secure, "smart-repair")
        case .continuity: (.secure, "continuity")
        case .direct: (.direct, "smart")
        }
    }
    static func matching(mode: TransportMode, policy: String) -> ConnectionPreset {
        if mode == .direct { return .direct }
        return policy == "continuity" ? .continuity : policy == "smart-repair" ? .smart : .bonded
    }
    /// Presets on the same transport switch while connected: the tunnel takes
    /// its new policy over the control channel and the UDP engine its new
    /// mode in place, so a running stream never sees a reconnect. Direct is a
    /// different transport and needs one. (Measured 2026-10-20: every
    /// disconnect/reconnect broke OBS's SRT connection for about 2 s.)
    func canSwitchLive(to other: ConnectionPreset) -> Bool {
        settings.mode == other.settings.mode
    }
    /// What the picker offers: everything when disconnected, only the presets
    /// reachable without a reconnect while connected.
    static func selectable(connected: Bool, current: ConnectionPreset) -> [ConnectionPreset] {
        connected ? allCases.filter { current.canSwitchLive(to: $0) } : allCases
    }
    var description: String {
        switch self {
        case .bonded:
            "Speed. The encrypted VERZ server combines every healthy WAN. UDP traffic is divided by measured delivered capacity, so faster links carry more; missing packets are repaired on request and traffic shifts when a link slows or fails."
        case .smart:
            "Recommended. Every packet is sent once, and small repair packets replace the copies Maximum Continuity sends: a failed, slow or lossy link is covered with a fraction of the data, and failures are noticed in tens of milliseconds. Needs a server with the update; until then it runs as Maximum Continuity."
        case .continuity:
            "Maximum protection. The encrypted VERZ server sends additional copies on multiple WANs to mask a link failure. This uses more data, and every protection WAN must be able to carry the protected traffic."
        case .direct:
            "No server. Each connection is pinned to one adapter and ISP for its whole life, so loss, congestion or an outage on that ISP hits it directly and nothing can carry or repair it over the other link. Only new connections can pick a better adapter."
        }
    }
}

/// When the tunnel ends on its own (a crash, a server restart, a network
/// change it could not ride out), the app brings it back by itself: quickly
/// at first, then at a steady pace, for up to ten minutes before it gives up
/// and tells the user. The stream lane keeps running throughout, so a video
/// stream never notices (measured 2026-10-20: the lane carried a stream at
/// full rate through 15 s of a frozen tunnel).
struct RecoveryPolicy {
    static let delays: [TimeInterval] = [1, 2, 4, 8, 16, 30]
    static let giveUpAfter: TimeInterval = 600
    private(set) var attempts = 0
    private(set) var startedAt: Date?
    var active: Bool { startedAt != nil }
    /// Seconds to wait before the next attempt, or nil once it is time to stop.
    mutating func nextDelay(now: Date = Date()) -> TimeInterval? {
        let started = startedAt ?? now
        startedAt = started
        if now.timeIntervalSince(started) > Self.giveUpAfter { return nil }
        let delay = Self.delays[min(attempts, Self.delays.count - 1)]
        attempts += 1
        return delay
    }
    mutating func reset() { attempts = 0; startedAt = nil }
    func elapsed(now: Date = Date()) -> TimeInterval { startedAt.map { now.timeIntervalSince($0) } ?? 0 }
}

struct NormalizedConnectionSettings: Equatable {
    let mode: TransportMode
    let policy: String
    let avoidMeteredLinks: Bool
}

/// Migrate legacy/internal combinations to one of the three supported customer
/// outcomes. The removed adaptive mode becomes Bonded; the old Data Saver mode
/// becomes Bonded plus the orthogonal metered-link preference.
func normalizedConnectionSettings(mode: TransportMode, policy: String,
                                  avoidMeteredLinks: Bool) -> NormalizedConnectionSettings {
    if mode == .direct {
        return NormalizedConnectionSettings(mode: .direct, policy: "smart",
                                            avoidMeteredLinks: avoidMeteredLinks || policy == "data-saver")
    }
    return NormalizedConnectionSettings(mode: .secure,
                                        policy: ["continuity", "smart-repair"].contains(policy) ? policy : "performance",
                                        avoidMeteredLinks: avoidMeteredLinks || policy == "data-saver")
}

/// The policy the main encrypted tunnel (TCP and uncaptured UDP) runs under.
/// Smart Repair changes only the UDP stream lane; the tunnel runs as Bonded,
/// and the privileged helper accepts only its own policy names.
func mainTunnelPolicy(_ policy: String) -> String {
    policy == "smart-repair" ? "performance" : policy
}

func avoidedMeteredInterfaces(_ interfaces: [LinkInterface], explicitlyDisabled: Set<String>,
                              metered: Set<String>, enabled: Bool) -> Set<String> {
    guard enabled else { return [] }
    let candidates = interfaces.filter { $0.canConnect && !explicitlyDisabled.contains($0.name) }
    guard candidates.contains(where: { !metered.contains($0.name) }) else { return [] }
    return Set(candidates.lazy.filter { metered.contains($0.name) }.map(\.name))
}

struct PathTelemetry: Decodable, Identifiable {
    let id: Int
    let name: String
    let state: String
    let enabled: Bool
    let rttMs: Double?
    let jitterMs: Double
    let sentBytes: UInt64
    let receivedBytes: UInt64
    let acknowledgedBytes: UInt64
    let deliveryBps: Double
    var carrier: String?
    var standby: Bool?
    var latencyExcluded: Bool?
    var realtimePreferred: Bool?
    var uploadBps: Double?
    var downloadBps: Double?
    var activeFlows: UInt64?
    var uploadHeld: Bool?
    var tcpObserved: Bool?
}
struct BondTelemetry: Decodable {
    // Retain the optional engine field for telemetry compatibility, not display.
    var payload: PayloadTelemetry?
    let paths: [PathTelemetry]
    let healthyPaths: Int
    let assignedIp: String
    let serverIp: String
    var trafficShape: String?
    var balancedChampion: String?
    var downloadChampion: String?
    var uploadChampion: String?
    var downloadGuarded: Bool?
    var uploadGuarded: Bool?
}

struct UDPPathTelemetry {
    let healthy: Bool
    let rtt: Double
    let capacityMbps: Double?
    let sent: UInt64
    let received: UInt64
    let uploadMbps: Double
    let downloadMbps: Double
}

struct UDPProviderTelemetry: Decodable {
    let payload: PayloadTelemetry?
}

struct BrainState: Decodable {
    let connected: Bool
    let generation: UInt64
    let strategy: String
    var learnedPaths: Int?
}

@MainActor
final class LinkModel: ObservableObject {
    @Published var state = ConnectionState.disconnected
    @Published var relay = "69.164.213.57:443"
    @Published var selectedInterface = "en0"
    @Published var interfaces: [LinkInterface] = []
    @Published var tunnelInterface = ""
    @Published var publicIP: String?
    @Published var errorMessage: String?
    @Published var hasCredential = false
    @Published var testRunning = false
    @Published var testProgress = 0.0
    @Published var testStage = ""
    @Published var result: TestResult?
    @Published var activity: [ActivityEntry] = []
    @Published var samples: [TrafficSample] = []
    @Published var receivedBytes: UInt64 = 0
    @Published var sentBytes: UInt64 = 0
    @Published var receivedMbps = 0.0
    @Published var sentMbps = 0.0
    @Published var uptime = 0
    @Published var selectedPage = "Connection"
    @Published var policy = "smart-repair" { didSet { configurationChanged() } }
    @Published var mode = TransportMode.secure { didSet { configurationChanged() } }
    @Published var avoidMeteredLinks = false { didSet { configurationChanged() } }
    /// Automatic tunnel recovery (RecoveryPolicy): non-empty while the tunnel
    /// ended on its own and the app is bringing it back, stream lane kept up.
    @Published var recoveryDetail = ""
    private var recovery = RecoveryPolicy()
    private var recoveryTask: Task<Void, Never>?
    /// The user pressed Disconnect: an ending session is a stop, not a fault.
    private var userStopped = false
    private var lastEngineError: String?
    private var pathsLostAt: Date?
    var preset: ConnectionPreset {
        get { ConnectionPreset.matching(mode: mode, policy: policy) }
        set {
            let settings = newValue.settings
            // While connected only a same-transport switch is applied; it
            // reaches the tunnel and the UDP engine as live configuration.
            if busy && !preset.canSwitchLive(to: newValue) { return }
            let live = busy && newValue != preset
            if mode != settings.mode { mode = settings.mode }
            if policy != settings.policy { policy = settings.policy }
            if live { log("Switched to \(newValue.title) without reconnecting") }
        }
    }
    @Published var secureDomainsText = "" { didSet { configurationChanged() } }
    @Published var disabledInterfaces = Set<String>()
    @Published var meteredInterfaces = Set<String>()
    @Published var bondTelemetry: BondTelemetry?
    /// Live per-path wire rate in Mbps, from consecutive engine reports.
    @Published var pathRates: [String: (upMbps: Double, downMbps: Double)] = [:]
    private var pathRateSample: (at: Date, paths: [String: (sent: UInt64, received: UInt64)])?
    @Published var udpPaths: [String: UDPPathTelemetry] = [:]
    /// Whether the connected server supports Smart Repair, once known.
    @Published var smartRepairSupported: Bool?
    @Published var smartRepairsSent: UInt64 = 0
    private var udpTelemetryTime: Date?
    private var udpPayloadMeter = PayloadRateTracker()
    private var interfaceReceivedMbps = 0.0
    private var interfaceSentMbps = 0.0
    @Published var privateServerIP = "10.78.0.1"
    @Published var brainConnected = false
    @Published var brainGeneration: UInt64 = 0
    @Published var brainStrategy = "local-fallback"
    @Published var brainLearnedPaths = 0
    private var directHealthyPaths = 0
    private var secureHealthyPaths = 0
    private var connectedAt: Date?
    private var lastInterfaceCounters: [String: (UInt64, UInt64)] = [:]
    private var lastSampleAt: Date?
    private var timer: Timer?
    private var interfaceMonitor: InterfaceMonitor?
    private var session: TunnelSession?
    private let udpConnection = UDPConnection()
    private var udpAcceleratorStarted = false
    private var runner: NetworkTest?
    private var testTask: Task<Void, Never>?
    private var sessionID = UUID()
    private var restorationFailed = false
    private var proxyEndpoint: String?
    private var initialized = false
    var whenDisconnected: (() -> Void)?

    let storage: URL
    // Opt-in, local-only transport diagnostics. One bounded snapshot, no
    // packet contents or credentials; disk I/O stays off the UI/event queue.
    private let transportDiagnosticQueue = DispatchQueue(label: "com.verz.link.tcp-diagnostics", qos: .utility)
    private var lastTransportDiagnostic = Date.distantPast
    private var lastUDPDiagnostic = Date.distantPast
    var busy: Bool { state != .disconnected }
    var canTest: Bool { state == .connected && mode != .direct && !testRunning }
    var effectiveDisabledInterfaces: Set<String> {
        disabledInterfaces.union(avoidedMeteredInterfaces(interfaces,
                                                          explicitlyDisabled: disabledInterfaces,
                                                          metered: meteredInterfaces,
                                                          enabled: avoidMeteredLinks))
    }
    var enabledInterfaces: [LinkInterface] {
        interfaces.filter { $0.canConnect && !effectiveDisabledInterfaces.contains($0.name) }
    }
    var visibleInterfaces: [LinkInterface] { interfaces.filter(\.isConnected) }
    var hasReadyInterface: Bool { !enabledInterfaces.isEmpty }
    var keyURL: URL { storage.appendingPathComponent("lab-secret") }

    init() {
        // Preserve this old app's preferences when moving its signing identity
        // to the paid team required by the Network Extension.
        if UserDefaults.standard.object(forKey: "classicUDPMigrated") == nil {
            let old = UserDefaults.standard.persistentDomain(forName: "com.verz.link.mac") ?? [:]
            for name in ["relay", "interface", "disabledInterfaces", "meteredInterfaces", "bondPolicy", "transportMode", "secureDomains"] {
                if UserDefaults.standard.object(forKey: name) == nil, let value = old[name] { UserDefaults.standard.set(value, forKey: name) }
            }
            UserDefaults.standard.set(true, forKey: "classicUDPMigrated")
        }
        storage = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/VERZ Link", isDirectory: true)
        try? FileManager.default.createDirectory(at: storage, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        if let value = UserDefaults.standard.string(forKey: "relay") { relay = value }
        if relay == "69.164.213.57:39001" { relay = "69.164.213.57:443" }
        if relay == "69.164.213.57:39002" { relay = "69.164.213.57:443" }
        disabledInterfaces = Set(UserDefaults.standard.stringArray(forKey: "disabledInterfaces") ?? [])
        meteredInterfaces = Set(UserDefaults.standard.stringArray(forKey: "meteredInterfaces") ?? [])
        // Smart Repair is the default since 2026-10-20: measured on the live
        // relay it rebuilds a lossy link's packets and rides out a cable pull
        // without a visible gap, at a fraction of Continuity's data.
        let savedPolicy = UserDefaults.standard.string(forKey: "bondPolicy") ?? "smart-repair"
        let savedMode = TransportMode(rawValue: UserDefaults.standard.string(forKey: "transportMode") ?? "secure") ?? .secure
        let normalized = normalizedConnectionSettings(
            mode: savedMode,
            policy: savedPolicy,
            avoidMeteredLinks: UserDefaults.standard.bool(forKey: "avoidMeteredLinks"))
        policy = normalized.policy
        mode = normalized.mode
        avoidMeteredLinks = normalized.avoidMeteredLinks
        UserDefaults.standard.set(policy, forKey: "bondPolicy")
        UserDefaults.standard.set(mode.rawValue, forKey: "transportMode")
        UserDefaults.standard.set(avoidMeteredLinks, forKey: "avoidMeteredLinks")
        secureDomainsText = UserDefaults.standard.string(forKey: "secureDomains") ?? ""
        if let value = UserDefaults.standard.string(forKey: "interface") { selectedInterface = value }
        hasCredential = validSecret((try? Data(contentsOf: keyURL)) ?? Data())
        if let data = try? Data(contentsOf: storage.appendingPathComponent("last-test.json")) {
            result = try? JSONDecoder().decode(TestResult.self, from: data)
        }
        refreshInterfaces()
        interfaceMonitor = InterfaceMonitor { [weak self] interfaces in
            Task { @MainActor in self?.updateInterfaces(interfaces) }
        }
        log("VERZ Link ready")
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sampleTraffic() }
        }
        initialized = true
        udpConnection.onMessage = { [weak self] text in self?.log(text) }
        udpConnection.onFailure = { [weak self] text in
            guard let self else { return }
            self.udpAcceleratorStarted = false
            self.udpPaths = [:]
            self.log("\(text) UDP traffic remains protected by the main encrypted tunnel.")
        }
        udpConnection.onTelemetry = { [weak self] data in
            guard let self, let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return }
            let now = Date()
            // The UDP lane's latest status next to the tunnel's, under the same
            // opt-in diagnostics flag, so the lane can be observed after a fault.
            if UserDefaults.standard.bool(forKey: "TCPTransportDiagnostics"),
               now.timeIntervalSince(self.lastUDPDiagnostic) >= 1, data.count <= 262_144 {
                self.lastUDPDiagnostic = now
                let destination = self.storage.appendingPathComponent("udp-status-latest.json")
                self.transportDiagnosticQueue.async { try? data.write(to: destination, options: .atomic) }
            }
            let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
            if let payload = try? decoder.decode(UDPProviderTelemetry.self, from: data).payload {
                let previousUploaded = self.udpPayloadMeter.uploaded
                let previousDownloaded = self.udpPayloadMeter.downloaded
                self.udpPayloadMeter.receive(payload, at: now.timeIntervalSinceReferenceDate)
                self.sentBytes += self.udpPayloadMeter.uploaded - previousUploaded
                self.receivedBytes += self.udpPayloadMeter.downloaded - previousDownloaded
                self.refreshHeadlineRates(at: now)
            }
            let elapsed = self.udpTelemetryTime.map { now.timeIntervalSince($0) } ?? 0
            let names = object["adapters"] as? [String: String] ?? [:]
            let wire = object["wire"] as? [String: [String: NSNumber]] ?? [:]
            var paths: [String: UDPPathTelemetry] = [:]
            for path in object["paths"] as? [[String: Any]] ?? [] {
                guard let id = path["id"] as? Int, let name = names[String(id)] else { continue }
                let sent = wire[String(id)]?["sent"]?.uint64Value ?? 0
                let received = wire[String(id)]?["received"]?.uint64Value ?? 0
                let old = self.udpPaths[name]
                let up = elapsed > 0 && old != nil && sent >= old!.sent ? Double(sent - old!.sent) * 8 / elapsed / 1_000_000 : 0
                let down = elapsed > 0 && old != nil && received >= old!.received ? Double(received - old!.received) * 8 / elapsed / 1_000_000 : 0
                paths[name] = UDPPathTelemetry(healthy: (path["status"] as? Int) == 1,
                    rtt: (path["rtt"] as? NSNumber)?.doubleValue ?? 0,
                    capacityMbps: (path["capacity"] as? NSNumber).flatMap {
                        $0.doubleValue > 0 ? $0.doubleValue / 1_000_000 : nil
                    },
                    sent: sent, received: received,
                    uploadMbps: up, downloadMbps: down)
            }
            self.udpPaths = paths; self.udpTelemetryTime = now
            if let smart = object["smart"] as? [String: Any], let supported = smart["supported"] as? Bool {
                if self.policy == "smart-repair", self.smartRepairSupported != supported {
                    self.log(supported ? "Smart Repair active · lost packets are rebuilt from repair packets"
                                       : "Smart Repair unavailable on this server · running as Maximum Continuity")
                }
                self.smartRepairSupported = supported
                self.smartRepairsSent = ((smart["stats"] as? [String: Any])?["repairs"] as? NSNumber)?.uint64Value ?? 0
            }
        }
    }

    func log(_ text: String) {
        activity.append(ActivityEntry(message: text))
        if activity.count > 300 { activity.removeFirst(activity.count - 300) }
        recordActivity(text)
    }

    /// The Activity log on disk (`activity.log` next to the other diagnostics),
    /// one timestamped line per entry, kept under about 2 MB. Local only. It is
    /// what lets a tunnel restart be explained after the fact instead of asked
    /// about.
    private func recordActivity(_ text: String) {
        let url = storage.appendingPathComponent("activity.log")
        let stamp = ISO8601DateFormatter.string(from: Date(), timeZone: .current,
                                               formatOptions: [.withInternetDateTime, .withFractionalSeconds])
        guard let data = (stamp + " " + text + "\n").data(using: .utf8) else { return }
        transportDiagnosticQueue.async {
            if let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue,
               size > 2_000_000, let whole = try? Data(contentsOf: url) {
                try? whole.suffix(1_000_000).write(to: url, options: .atomic)
            }
            if let handle = try? FileHandle(forWritingTo: url) {
                defer { try? handle.close() }
                _ = try? handle.seekToEnd()
                try? handle.write(contentsOf: data)
            } else {
                try? data.write(to: url, options: .atomic)
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
        }
    }

    /// One JSON line per direct/relay flow from the engine: placement inputs and
    /// delivered outcome, destinations hashed. Local only; this is the dataset
    /// any future policy or model must be replayed against before it ships.
    private func recordFlow(_ line: String) {
        let directory = storage.appendingPathComponent("flows", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let day = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withFullDate])
        let url = directory.appendingPathComponent("\(day).jsonl")
        guard let data = (line + "\n").data(using: .utf8) else { return }
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            try? data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }

    func connect() {
        guard !busy else { return }
        userStopped = false
        recoveryTask?.cancel(); recoveryTask = nil
        recovery.reset(); recoveryDetail = ""
        start(recovering: false)
    }

    /// Brings the tunnel up. While recovering, the UDP stream lane is left
    /// running and a failed attempt schedules the next one instead of
    /// surfacing an error.
    private func start(recovering: Bool) {
        if recovering { guard !userStopped else { return } } else { guard !busy else { return } }
        errorMessage = nil
        refreshInterfaces()
        guard hasReadyInterface else {
            if recovering, scheduleRecovery(reason: "no usable uplink yet") { return }
            errorMessage = "No usable uplink. Connect Wi-Fi or Ethernet and wait for an IPv4 address."; return
        }
        var secret = Data()
        if mode != .direct {
            let parts = relay.split(separator: ":")
            var address = in_addr()
            guard parts.count == 2, inet_pton(AF_INET, String(parts[0]), &address) == 1,
                  let port = Int(parts[1]), (1...65535).contains(port) else {
                errorMessage = "Enter a valid Secure Continuity relay IPv4 address and port."; return
            }
            guard let installed = try? Data(contentsOf: keyURL), validSecret(installed) else {
                errorMessage = "Import your Secure Continuity key in Settings first."; selectedPage = "Settings"; return
            }
            secret = installed
            if mode == .hybrid && secureDomains() == nil {
                errorMessage = "Secure-domain rules must be valid domain suffixes, one per line or separated by commas."
                selectedPage = "Settings"
                return
            }
        }
        UserDefaults.standard.set(relay, forKey: "relay")
        UserDefaults.standard.set(selectedInterface, forKey: "interface")
        state = recovering ? .reconnecting : .authorizing
        restorationFailed = false
        publicIP = nil; proxyEndpoint = nil; samples = []; lastInterfaceCounters = [:]; lastSampleAt = nil; bondTelemetry = nil
        pathRates = [:]; pathRateSample = nil
        sentBytes = 0; receivedBytes = 0; sentMbps = 0; receivedMbps = 0
        interfaceReceivedMbps = 0; interfaceSentMbps = 0
        if !recovering {
            // A fresh connection starts the stream lane over; a recovery keeps
            // it running, so a stream in flight never notices the tunnel.
            udpPaths = [:]; udpTelemetryTime = nil; udpPayloadMeter = PayloadRateTracker()
            udpAcceleratorStarted = false
            udpConnection.disconnect()
        }
        brainConnected = false; brainGeneration = 0; brainStrategy = "local-fallback"
        directHealthyPaths = 0; secureHealthyPaths = 0
        sessionID = UUID()
        let identifier = sessionID
        let names = enabledInterfaces.map(\.name)
        if recovering {
            log("Reconnecting the tunnel (attempt \(recovery.attempts)) using \(names.joined(separator: ", ")) · stream lane stays up")
        } else {
            log("Starting \(mode.title) using \(names.joined(separator: ", ")) · \(policy)")
        }
        startTunnel(secret: secret, names: names, identifier: identifier, recovering: recovering)
    }

    private func startTunnel(secret: Data, names: [String], identifier: UUID, recovering: Bool) {
        do {
            session = try TunnelSession(secret: secret, relay: relay, interfaces: names, policy: mainTunnelPolicy(policy), configuration: configurationData()) { [weak self] event in
                Task { @MainActor in
                    guard let self, self.sessionID == identifier else { return }
                    self.handle(event)
                }
            }
        } catch {
            log(error.localizedDescription)
            if recovering, scheduleRecovery(reason: error.localizedDescription) { return }
            udpConnection.disconnect(); state = .disconnected; errorMessage = error.localizedDescription
        }
    }

    /// Plans the next recovery attempt. Returns false once the policy says to
    /// stop, leaving the caller to disconnect for good.
    @discardableResult
    private func scheduleRecovery(reason: String) -> Bool {
        guard !userStopped, let delay = recovery.nextDelay() else { return false }
        state = .reconnecting
        session = nil
        let attempt = recovery.attempts
        recoveryDetail = "Reconnecting · attempt \(attempt) in \(Int(delay)) s · \(reason) · stream lane active"
        log("Tunnel ended: \(reason) · reconnecting in \(Int(delay)) s (attempt \(attempt)); the UDP stream lane stays up")
        recoveryTask?.cancel()
        recoveryTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run { [weak self] in
                guard let self, !self.userStopped, self.session == nil else { return }
                self.start(recovering: true)
            }
        }
        return true
    }

    private func startUDPAccelerator(identifier: UUID) {
        guard mode != .direct, !udpAcceleratorStarted,
              let secret = try? Data(contentsOf: keyURL), validSecret(secret) else { return }
        udpAcceleratorStarted = true
        udpConnection.connect(host: String(relay.split(separator: ":")[0]),
                              key: String(decoding: secret, as: UTF8.self)
                                .trimmingCharacters(in: .whitespacesAndNewlines),
                              disabled: Array(effectiveDisabledInterfaces), policy: policy) { [weak self] result in
            guard let self, self.sessionID == identifier, self.state != .disconnecting else { return }
            switch result {
            case .success:
                self.log("UDP accelerator active · native UDP when available, encrypted main-tunnel fallback otherwise")
            case .failure(let error):
                self.udpAcceleratorStarted = false
                self.log("UDP accelerator unavailable: \(error.localizedDescription). UDP remains on the encrypted main tunnel.")
            }
        }
    }

    func disconnect() {
        guard busy else { return }
        userStopped = true
        recoveryTask?.cancel(); recoveryTask = nil
        recovery.reset(); recoveryDetail = ""
        runner?.cancel(); testTask?.cancel(); testRunning = false
        state = .disconnecting
        udpAcceleratorStarted = false
        log("Disconnect requested")
        udpConnection.disconnect()
        if let session { session.disconnect() } else { state = .disconnected }
    }

    private func handle(_ event: EngineEvent) {
        switch event.event {
        case "helper_ready": if state != .disconnecting { state = .connecting }
        case "configuring":
            if state != .disconnecting { state = .connecting }
            log(event.line ?? "Configuring network")
        case "connected":
            guard state != .disconnecting else { session?.disconnect(); return }
            if recovery.active {
                log("Tunnel recovered after \(Int(recovery.elapsed())) s and \(recovery.attempts) attempt(s)")
                recovery.reset(); recoveryDetail = ""; lastEngineError = nil
            }
            pathsLostAt = nil
            state = .connected; connectedAt = Date(); uptime = 0
            let endpoint = event.line?.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
            if mode == .secure {
                tunnelInterface = endpoint
                log("Secure Continuity connected · traffic and DNS routed through the encrypted relay")
            } else {
                proxyEndpoint = endpoint
                tunnelInterface = ""
                if mode == .hybrid {
                    log("Automatic Hybrid connected · direct-first flows with encrypted selective relay escalation")
                } else {
                    log("Direct Smart connected · TCP flows go directly to their destinations")
                }
            }
            startUDPAccelerator(identifier: sessionID)
            let token = sessionID
            Task { [weak self] in
                let ip = await Self.fetchPublicIP(proxy: self?.mode == .secure ? nil : self?.proxyEndpoint)
                guard let self, self.state == .connected, self.sessionID == token else { return }
                self.publicIP = ip
                self.log(ip.map { self.mode == .secure ? "Public IPv4 through relay: \($0)" : "Direct public IPv4: \($0)" }
                    ?? "Public IP check unavailable; connection remains active")
                if self.mode == .secure, let ip, ip != self.relay.split(separator: ":").first.map(String.init) {
                    self.errorMessage = "Public IP does not match the relay. Verify routing before relying on this connection."
                }
            }
        case "telemetry":
            if let line = event.line, let data = line.data(using: .utf8) {
                if UserDefaults.standard.bool(forKey: "TCPTransportDiagnostics"),
                   Date().timeIntervalSince(lastTransportDiagnostic) >= 1, data.count <= 262_144 {
                    lastTransportDiagnostic = Date()
                    let destination = storage.appendingPathComponent("tcp-transport-latest.json")
                    transportDiagnosticQueue.async {
                        try? data.write(to: destination, options: .atomic)
                    }
                }
                let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
                if let report = try? decoder.decode(BondTelemetry.self, from: data) {
                    secureHealthyPaths = report.healthyPaths
                    if mode == .hybrid {
                        if !report.serverIp.isEmpty { privateServerIP = report.serverIp }
                        evaluateAvailability()
                        return
                    }
                    let previous = bondTelemetry
                    bondTelemetry = report
                    updatePathRates(report)
                    if !report.serverIp.isEmpty { privateServerIP = report.serverIp }
                    for path in report.paths {
                        if previous?.paths.first(where: { $0.name == path.name })?.state != path.state {
                            log("\(path.name): \(path.state)")
                        }
                    }
                    if state == .connected && report.healthyPaths == 0 {
                        state = .reconnecting; log("All paths unavailable · preserving the tunnel while networks recover")
                    } else if state == .reconnecting && report.healthyPaths > 0 {
                        state = .connected; log("Delivery restored over \(report.healthyPaths) healthy path(s)")
                    }
                    if report.healthyPaths == 0 {
                        // A server that restarted has forgotten this session:
                        // the tunnel stays silent although an uplink is fine.
                        // Thirty seconds of that is a restart, not a wait.
                        let lost = pathsLostAt ?? Date()
                        pathsLostAt = lost
                        if Date().timeIntervalSince(lost) > 30, hasReadyInterface, let session {
                            pathsLostAt = nil
                            log("No path has answered for 30 s while an uplink is ready · restarting the tunnel")
                            session.disconnect()
                        }
                    } else {
                        pathsLostAt = nil
                    }
                }
            }
        case "direct_telemetry":
            if let line = event.line, let data = line.data(using: .utf8) {
                let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
                if let report = try? decoder.decode(BondTelemetry.self, from: data) {
                    let previous = bondTelemetry
                    bondTelemetry = report
                    updatePathRates(report)
                    directHealthyPaths = report.healthyPaths
                    for path in report.paths where previous?.paths.first(where: { $0.name == path.name })?.state != path.state {
                        log("\(path.name): \(path.state)")
                    }
                    evaluateAvailability()
                }
            }
        case "brain":
            if let line = event.line, let data = line.data(using: .utf8),
               let report = try? JSONDecoder().decode(BrainState.self, from: data) {
                let changed = brainConnected != report.connected
                brainConnected = report.connected
                brainGeneration = report.generation
                brainStrategy = report.strategy
                brainLearnedPaths = report.learnedPaths ?? 0
                if changed {
                    log(report.connected ? "Encrypted server brain connected · adaptive path advice active"
                        : "Server brain unavailable · local safe policy remains active")
                }
            }
        case "engine_error", "cleanup_error":
            if event.event == "cleanup_error" { restorationFailed = true }
            if let line = event.line { log(line); errorMessage = line; lastEngineError = line }
        case "flow":
            if let line = event.line { recordFlow(line) }
        case "launch_error":
            let text = event.line ?? "Unable to start the connection engine."
            let shown = text.contains("-128") ? "Connection cancelled at the macOS permission prompt." : text
            log(shown)
            // A permission refusal is the user's decision; anything else during
            // a recovery is one more failed attempt.
            if recovery.active, !text.contains("-128"), scheduleRecovery(reason: shown) { return }
            errorMessage = shown
        case "session_ended":
            tunnelInterface = ""; proxyEndpoint = nil; connectedAt = nil; uptime = 0
            brainConnected = false; brainGeneration = 0; directHealthyPaths = 0; secureHealthyPaths = 0
            runner?.cancel(); testTask?.cancel(); testRunning = false
            session = nil; receivedMbps = 0; sentMbps = 0; publicIP = nil
            interfaceReceivedMbps = 0; interfaceSentMbps = 0
            let unexpected = !userStopped && state != .disconnecting
            if unexpected {
                let reason = lastEngineError ?? (event.code.map { "the tunnel ended (code \($0))" } ?? "the tunnel ended")
                if scheduleRecovery(reason: reason) { return }
                errorMessage = "The tunnel could not be restored for ten minutes. Disconnected."
                log(errorMessage!)
            }
            recovery.reset(); recoveryDetail = ""
            udpAcceleratorStarted = false
            udpConnection.disconnect()
            state = .disconnected; udpPayloadMeter = PayloadRateTracker()
            refreshInterfaces()
            log(restorationFailed ? "Disconnected · check Activity for network restoration errors" : "Disconnected · network restoration finished")
            whenDisconnected?(); whenDisconnected = nil
        case "log": if let line = event.line { log(line) }
        case "exited":
            // The decision whether this is a fault to recover from or a stop
            // is taken at session_ended; here only the reason is kept.
            if let code = event.code, code != 0, lastEngineError == nil { lastEngineError = "the tunnel ended unexpectedly (code \(code))" }
        default: break
        }
    }

    func runTest() {
        guard canTest, let upload = session?.engineURL else { return }
        errorMessage = nil; testRunning = true; testProgress = 0
        selectedPage = "Diagnostics"
        let test = NetworkTest(); runner = test
        log("Started real ICMP and file-transfer diagnostics")
        testTask = Task {
            do {
                let result = try await test.run(uploadFile: upload, serverIP: privateServerIP) { [weak self] progress, stage in
                    Task { @MainActor in self?.testProgress = progress; self?.testStage = stage }
                }
                guard !Task.isCancelled else { return }
                self.result = result; testRunning = false; testStage = "Complete · both checksums match"
                try? JSONEncoder().encode(result).write(to: storage.appendingPathComponent("last-test.json"), options: .atomic)
                log(String(format: "Diagnostics complete · %.2f ms average latency · %.1f%% ping loss · both files verified", result.averageMs, result.lossPercent))
            } catch {
                testRunning = false
                if Task.isCancelled || error is CancellationError { testStage = "Test cancelled" }
                else {
                    let message = NetworkTest.userFacingMessage(for: error)
                    errorMessage = message
                    testStage = "Test failed"
                    log("Diagnostics failed · \(message)")
                }
            }
        }
    }

    func importKey() {
        guard !busy else { return }
        let panel = NSOpenPanel()
        panel.title = "Import VERZ connection profile or key"; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            var data = try Data(contentsOf: url)
            if let profile = try? JSONDecoder().decode(ConnectionProfile.self, from: data) {
                guard (2...3).contains(profile.version), Self.validRelay(profile.relay) else {
                    throw LinkError.message("Unsupported profile version or invalid relay address.")
                }
                data = Data(profile.key.utf8)
                guard validSecret(data) else { throw LinkError.message("Invalid connection key in profile.") }
                relay = profile.relay
                if relay == "69.164.213.57:39001" { relay = "69.164.213.57:443" }
                if relay == "69.164.213.57:39002" { relay = "69.164.213.57:443" }
                UserDefaults.standard.set(relay, forKey: "relay")
            }
            guard validSecret(data) else { throw LinkError.message("The key must contain 64 hexadecimal characters.") }
            try data.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            hasCredential = true; errorMessage = nil; log("Connection key imported")
        } catch { errorMessage = error.localizedDescription }
    }

    func exportProfile() {
        guard let secret = try? Data(contentsOf: keyURL), validSecret(secret), Self.validRelay(relay) else {
            errorMessage = "A valid relay and connection key are required to export a profile."; return
        }
        let panel = NSSavePanel()
        panel.title = "Export private VERZ connection profile"
        panel.message = "Contains your relay access key. Transfer privately to your other Mac; do not post or share publicly."
        panel.nameFieldStringValue = "VERZ Connection.verz"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let profile = ConnectionProfile(version: 3, relay: relay,
                key: String(decoding: secret, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
            let data = try JSONEncoder().encode(profile)
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            log("Private connection profile exported")
        } catch { errorMessage = error.localizedDescription }
    }

    private static func validRelay(_ value: String) -> Bool {
        let parts = value.split(separator: ":")
        var ip = in_addr()
        return parts.count == 2 && inet_pton(AF_INET, String(parts[0]), &ip) == 1
            && Int(parts[1]).map { (1...65535).contains($0) } == true
    }

    func exportReport() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "VERZ Link Report.txt"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var text = "VERZ Link\nServer: \(relay)\nInterface: \(selectedInterface)\nPublic IPv4: \(publicIP ?? "unavailable")\n\n"
        if let result, let data = try? JSONEncoder().encode(result) { text += String(decoding: data, as: UTF8.self) + "\n\n" }
        text += activity.map { "\($0.date.formatted(date: .omitted, time: .standard))  \($0.message)" }.joined(separator: "\n")
        do { try text.write(to: url, atomically: true, encoding: .utf8) } catch { errorMessage = error.localizedDescription }
    }

    private func validSecret(_ data: Data) -> Bool {
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.count == 64 && text.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    func refreshInterfaces() {
        updateInterfaces(InterfaceInventory.snapshot())
    }

    private func updateInterfaces(_ found: [LinkInterface]) {
        let interfacesChanged = interfaces != found
        if interfacesChanged { interfaces = found }
        let selected = InterfaceInventory.selectedName(current: selectedInterface, busy: busy, interfaces: found)
        let selectionChanged = selectedInterface != selected
        if selectionChanged { selectedInterface = selected }
        // The monitor polls only as a safety net. Do not turn identical
        // snapshots into control messages: the UDP provider interprets an app
        // update as a request to refresh adapters, and the TCP engine should
        // receive configuration only for an actual carrier/address change.
        if interfacesChanged || selectionChanged { configurationChanged() }
    }

    func setInterface(_ name: String, enabled: Bool) {
        if enabled { disabledInterfaces.remove(name) } else { disabledInterfaces.insert(name) }
        UserDefaults.standard.set(Array(disabledInterfaces).sorted(), forKey: "disabledInterfaces")
        configurationChanged()
    }

    func setMetered(_ name: String, metered: Bool) {
        if metered { meteredInterfaces.insert(name) } else { meteredInterfaces.remove(name) }
        UserDefaults.standard.set(Array(meteredInterfaces).sorted(), forKey: "meteredInterfaces")
        configurationChanged()
    }

    private func configurationData() -> Data {
        let paths: [[String: Any]] = enabledInterfaces.map { ["name": $0.name, "address": $0.address ?? "", "metered": meteredInterfaces.contains($0.name)] }
        return (try? JSONSerialization.data(withJSONObject: [
            "interfaces": paths,
            "policy": mainTunnelPolicy(policy),
            "mode": mode.rawValue,
            "secureDomains": secureDomains() ?? []
        ], options: [.sortedKeys])) ?? Data()
    }

    private func configurationChanged() {
        guard initialized else { return }
        UserDefaults.standard.set(policy, forKey: "bondPolicy")
        UserDefaults.standard.set(mode.rawValue, forKey: "transportMode")
        UserDefaults.standard.set(avoidMeteredLinks, forKey: "avoidMeteredLinks")
        UserDefaults.standard.set(secureDomainsText, forKey: "secureDomains")
        session?.updateConfiguration(configurationData())
        if mode != .direct { udpConnection.update(disabled: Array(effectiveDisabledInterfaces), policy: policy) }
    }

    private func secureDomains() -> [String]? {
        var output: [String] = []
        let pieces = secureDomainsText.components(separatedBy: CharacterSet(charactersIn: ",\n"))
        for piece in pieces {
            let domain = piece.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "."))
                .lowercased()
            if domain.isEmpty { continue }
            let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
            guard domain.utf8.count <= 253, !labels.isEmpty,
                  labels.allSatisfy({ label in
                      label.utf8.count <= 63 && !label.isEmpty && !label.hasPrefix("-") && !label.hasSuffix("-")
                          && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
                  }) else { return nil }
            if !output.contains(domain) { output.append(domain) }
        }
        return output
    }

    private func evaluateAvailability() {
        guard state == .connected || state == .reconnecting else { return }
        let available = mode == .hybrid ? directHealthyPaths + secureHealthyPaths : directHealthyPaths
        if available == 0 && state == .connected {
            state = .reconnecting
            log("All paths unavailable · engines stay warm while networks recover")
        } else if available > 0 && state == .reconnecting {
            state = .connected
            log("Delivery restored without creating a new Hybrid session")
        }
    }

    private func updatePathRates(_ report: BondTelemetry) {
        let now = Date()
        let current = Dictionary(uniqueKeysWithValues: report.paths.map { ($0.name, (sent: $0.sentBytes, received: $0.receivedBytes)) })
        guard let last = pathRateSample else { pathRateSample = (now, current); return }
        let seconds = now.timeIntervalSince(last.at)
        guard seconds >= 0.2 else { return }
        pathRateSample = (now, current)
        var rates = pathRates
        for (name, counters) in current {
            // A rejoined path restarts its counters; treat a decrease as zero.
            let up = counters.sent >= (last.paths[name]?.sent ?? counters.sent) ? counters.sent - (last.paths[name]?.sent ?? counters.sent) : 0
            let down = counters.received >= (last.paths[name]?.received ?? counters.received) ? counters.received - (last.paths[name]?.received ?? counters.received) : 0
            let sample = (upMbps: Double(up) * 8 / seconds / 1_000_000, downMbps: Double(down) * 8 / seconds / 1_000_000)
            // Two-report smoothing hides 500 ms sampling jitter without lagging.
            if let old = rates[name] {
                rates[name] = (0.5 * old.upMbps + 0.5 * sample.upMbps, 0.5 * old.downMbps + 0.5 * sample.downMbps)
            } else {
                rates[name] = sample
            }
        }
        for name in rates.keys where current[name] == nil { rates[name] = (0, 0) }
        pathRates = rates
    }

    private func sampleTraffic() {
        guard state == .connected || state == .reconnecting else { return }
        if mode != .direct { udpConnection.telemetry() }
        uptime = Int(Date().timeIntervalSince(connectedAt ?? Date()))
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return }
        defer { freeifaddrs(list) }
        var cursor = list
        let monitored = mode == .secure ? Set([tunnelInterface]) : Set(enabledInterfaces.map(\.name))
        var current: [String: (UInt64, UInt64)] = [:]
        while let pointer = cursor {
            let item = pointer.pointee
            defer { cursor = item.ifa_next }
            let name = String(cString: item.ifa_name)
            guard monitored.contains(name),
                  item.ifa_addr?.pointee.sa_family == UInt8(AF_LINK), let data = item.ifa_data else { continue }
            let counters = data.assumingMemoryBound(to: if_data.self).pointee
            current[name] = (UInt64(counters.ifi_ibytes), UInt64(counters.ifi_obytes))
        }
        let now = Date()
        var receivedDelta: UInt64 = 0
        var sentDelta: UInt64 = 0
        let previousCounters = lastInterfaceCounters
        for (name, counters) in current {
            if let old = previousCounters[name] {
                receivedDelta += counters.0 >= old.0 ? counters.0 - old.0 : 0
                sentDelta += counters.1 >= old.1 ? counters.1 - old.1 : 0
            }
        }
        lastInterfaceCounters = current
        let seconds = max(lastSampleAt.map { now.timeIntervalSince($0) } ?? 1, 0.01)
        interfaceReceivedMbps = Double(receivedDelta) * 8 / seconds / 1_000_000
        interfaceSentMbps = Double(sentDelta) * 8 / seconds / 1_000_000
        receivedBytes += receivedDelta; sentBytes += sentDelta; lastSampleAt = now
        refreshHeadlineRates(at: now)
        samples.append(TrafficSample(received: receivedMbps, sent: sentMbps))
        if samples.count > 60 { samples.removeFirst(samples.count - 60) }
    }

    /// Secure Continuity's TCP engine is visible on its tunnel interface, while
    /// the independent UDP extension bypasses that interface. Add the UDP
    /// provider's unique application datagrams once; never add per-WAN wire
    /// counters because continuity copies would inflate the displayed speed.
    private func refreshHeadlineRates(at now: Date) {
        let udpRate = mode == .secure
            ? udpPayloadMeter.rate(at: now.timeIntervalSinceReferenceDate)
            : nil
        receivedMbps = interfaceReceivedMbps + (udpRate?.down ?? 0)
        sentMbps = interfaceSentMbps + (udpRate?.up ?? 0)
    }

    nonisolated private static func fetchPublicIP(proxy: String?) async -> String? {
        // A new curl process has no pre-VPN keep-alive connection to reuse.
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                let process = Process(); let pipe = Pipe()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.arguments = ["-4", "--silent", "--fail", "--max-time", "10"]
                    + (proxy.map { ["--socks5-hostname", $0] } ?? ["--noproxy", "*"])
                    + ["https://api.ipify.org"]
                process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
                do {
                    try process.run()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
                    let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    var address = in_addr()
                    continuation.resume(returning: process.terminationStatus == 0 && inet_pton(AF_INET, text, &address) == 1 ? text : nil)
                } catch { continuation.resume(returning: nil) }
            }
        }
    }
}
