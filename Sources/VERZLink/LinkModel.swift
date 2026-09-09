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
    var latencyExcluded: Bool?
    var realtimePreferred: Bool?
    var uploadBps: Double?
    var downloadBps: Double?
    var activeFlows: UInt64?
    var uploadHeld: Bool?
    var tcpObserved: Bool?
}
struct BondTelemetry: Decodable {
    let paths: [PathTelemetry]
    let healthyPaths: Int
    let assignedIp: String
    let serverIp: String
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
    @Published var relay = "69.164.213.57:39002"
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
    @Published var policy = "smart" { didSet { configurationChanged() } }
    @Published var mode = TransportMode.direct { didSet { configurationChanged() } }
    @Published var secureDomainsText = "" { didSet { configurationChanged() } }
    @Published var disabledInterfaces = Set<String>()
    @Published var meteredInterfaces = Set<String>()
    @Published var bondTelemetry: BondTelemetry?
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
    private var runner: NetworkTest?
    private var testTask: Task<Void, Never>?
    private var sessionID = UUID()
    private var restorationFailed = false
    private var proxyEndpoint: String?
    private var initialized = false
    var whenDisconnected: (() -> Void)?

    let storage: URL
    var busy: Bool { state != .disconnected }
    var canTest: Bool { state == .connected && mode != .direct && !testRunning }
    var enabledInterfaces: [LinkInterface] { interfaces.filter { $0.canConnect && !disabledInterfaces.contains($0.name) } }
    var visibleInterfaces: [LinkInterface] { interfaces.filter(\.isConnected) }
    var hasReadyInterface: Bool { !enabledInterfaces.isEmpty }
    var keyURL: URL { storage.appendingPathComponent("lab-secret") }

    init() {
        storage = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/VERZ Link", isDirectory: true)
        try? FileManager.default.createDirectory(at: storage, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        if let value = UserDefaults.standard.string(forKey: "relay") { relay = value }
        if relay == "69.164.213.57:39001" { relay = "69.164.213.57:39002" }
        disabledInterfaces = Set(UserDefaults.standard.stringArray(forKey: "disabledInterfaces") ?? [])
        meteredInterfaces = Set(UserDefaults.standard.stringArray(forKey: "meteredInterfaces") ?? [])
        policy = UserDefaults.standard.string(forKey: "bondPolicy") ?? "smart"
        mode = TransportMode(rawValue: UserDefaults.standard.string(forKey: "transportMode") ?? "direct") ?? .direct
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
    }

    func log(_ text: String) {
        activity.append(ActivityEntry(message: text))
        if activity.count > 300 { activity.removeFirst(activity.count - 300) }
    }

    func connect() {
        guard !busy else { return }
        errorMessage = nil
        refreshInterfaces()
        guard hasReadyInterface else {
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
        state = .authorizing
        restorationFailed = false
        publicIP = nil; proxyEndpoint = nil; samples = []; lastInterfaceCounters = [:]; lastSampleAt = nil; bondTelemetry = nil
        sentBytes = 0; receivedBytes = 0; sentMbps = 0; receivedMbps = 0
        brainConnected = false; brainGeneration = 0; brainStrategy = "local-fallback"
        directHealthyPaths = 0; secureHealthyPaths = 0
        sessionID = UUID()
        let identifier = sessionID
        let names = enabledInterfaces.map(\.name)
        log("Starting \(mode.title) using \(names.joined(separator: ", ")) · \(policy)")
        do {
            session = try TunnelSession(secret: secret, relay: relay, interfaces: names, policy: policy, configuration: configurationData()) { [weak self] event in
                Task { @MainActor in
                    guard let self, self.sessionID == identifier else { return }
                    self.handle(event)
                }
            }
        } catch { state = .disconnected; errorMessage = error.localizedDescription; log(error.localizedDescription) }
    }

    func disconnect() {
        guard busy else { return }
        runner?.cancel(); testTask?.cancel(); testRunning = false
        state = .disconnecting
        log("Disconnect requested")
        session?.disconnect()
    }

    private func handle(_ event: EngineEvent) {
        switch event.event {
        case "helper_ready": if state != .disconnecting { state = .connecting }
        case "configuring":
            if state != .disconnecting { state = .connecting }
            log(event.line ?? "Configuring network")
        case "connected":
            guard state != .disconnecting else { session?.disconnect(); return }
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
                }
            }
        case "direct_telemetry":
            if let line = event.line, let data = line.data(using: .utf8) {
                let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
                if let report = try? decoder.decode(BondTelemetry.self, from: data) {
                    let previous = bondTelemetry
                    bondTelemetry = report
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
            if let line = event.line { log(line); errorMessage = line }
        case "launch_error":
            let text = event.line ?? "Unable to start the Rust engine."
            errorMessage = text.contains("-128") ? "Connection cancelled at the macOS permission prompt." : text
            log(errorMessage!)
        case "session_ended":
            state = .disconnected; tunnelInterface = ""; proxyEndpoint = nil; connectedAt = nil; uptime = 0
            brainConnected = false; brainGeneration = 0; directHealthyPaths = 0; secureHealthyPaths = 0
            runner?.cancel(); testTask?.cancel(); testRunning = false
            session = nil; receivedMbps = 0; sentMbps = 0; publicIP = nil
            refreshInterfaces()
            log(restorationFailed ? "Disconnected · check Activity for network restoration errors" : "Disconnected · network restoration finished")
            whenDisconnected?(); whenDisconnected = nil
        case "log": if let line = event.line { log(line) }
        case "exited": if event.code != 0 && errorMessage == nil { errorMessage = "The tunnel ended unexpectedly. See Activity for details." }
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
                else { errorMessage = error.localizedDescription; testStage = "Test failed"; log("Diagnostics failed: \(error.localizedDescription)") }
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
                if relay == "69.164.213.57:39001" { relay = "69.164.213.57:39002" }
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
        if interfaces != found { interfaces = found }
        selectedInterface = InterfaceInventory.selectedName(current: selectedInterface, busy: busy, interfaces: found)
        configurationChanged()
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
            "policy": policy,
            "mode": mode.rawValue,
            "secureDomains": secureDomains() ?? []
        ], options: [.sortedKeys])) ?? Data()
    }

    private func configurationChanged() {
        guard initialized else { return }
        UserDefaults.standard.set(policy, forKey: "bondPolicy")
        UserDefaults.standard.set(mode.rawValue, forKey: "transportMode")
        UserDefaults.standard.set(secureDomainsText, forKey: "secureDomains")
        session?.updateConfiguration(configurationData())
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

    private func sampleTraffic() {
        guard state == .connected || state == .reconnecting else { return }
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
        receivedMbps = Double(receivedDelta) * 8 / seconds / 1_000_000
        sentMbps = Double(sentDelta) * 8 / seconds / 1_000_000
        receivedBytes += receivedDelta; sentBytes += sentDelta; lastSampleAt = now
        samples.append(TrafficSample(received: receivedMbps, sent: sentMbps))
        if samples.count > 60 { samples.removeFirst(samples.count - 60) }
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
