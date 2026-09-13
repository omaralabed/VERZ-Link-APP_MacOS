import Foundation
import NetworkExtension
import class Network.NWPathMonitor
import SystemConfiguration
import Darwin

final class TransparentProvider: NETransparentProxyProvider {
    private let work = DispatchQueue(label: "com.verz.link.macos2.engine", qos: .userInitiated)
    private lazy var scanner = UDPInterfaceScanner(owner: work)
    private var engine: UnsafeMutableRawPointer?
    private var timer: DispatchSourceTimer?
    private let monitor = NWPathMonitor()
    private var ticks = 0
    private var ids: [String: UInt8] = [:]
    private var nextID: UInt16 = 1
    private var nextFlow: UInt32 = 1
    private var flows: [UInt16: NEAppProxyUDPFlow] = [:]
    private var pendingWrites: [UInt16: Int] = [:]
    private var gatewayHost = ""
    private var disabled = Set<String>()
    private var startup: ((Error?) -> Void)?
    private var startTime = Date()
    private var localDrops: UInt64 = 0
    private var lastPump: UInt64?
    private var maxPumpGapMS = 0.0
    private var maxInventoryMS = 0.0
    private var maxAdapterApplyMS = 0.0
    private var payloadSource = UUID().uuidString
    private var payloadEpoch = ProcessInfo.processInfo.systemUptime
    private var payloadSent: UInt64 = 0
    private var payloadReceived: UInt64 = 0

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        work.async {
            guard let config = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                  let gateway = config["gateway"] as? String,
                  let session = config["session"] as? Int,
                  let key = options?["key"] as? String, key.utf8.count >= 32,
                  let data = try? JSONSerialization.data(withJSONObject: ["gateway":gateway,"session":session,"key":key]) else {
                completionHandler(self.failure("Missing gateway enrollment")); return
            }
            self.gatewayHost = gateway.components(separatedBy: ":")[0]
            self.payloadSource = UUID().uuidString
            self.payloadEpoch = ProcessInfo.processInfo.systemUptime
            self.payloadSent = 0; self.payloadReceived = 0
            self.disabled = Set(config["disabled"] as? [String] ?? [])
            self.engine = data.withUnsafeBytes { verz_create($0.bindMemory(to: UInt8.self).baseAddress, data.count) }
            guard self.engine != nil else {completionHandler(self.failure("Rust engine rejected enrollment")); return}
            verz_mode(self.engine, Int32(config["mode"] as? Int ?? 0))
            self.scan()
            self.monitor.pathUpdateHandler = { [weak self] _ in self?.work.async { self?.scan() } }
            self.monitor.start(queue: DispatchQueue(label: "com.verz.link.macos2.path-events"))
            let settings = UDPCaptureRules.settings(gateway: self.gatewayHost)
            self.setTunnelNetworkSettings(settings) { error in
                self.work.async {
                    if let error {self.cleanup();completionHandler(error);return}
                    let timer = DispatchSource.makeTimerSource(queue: self.work)
                    timer.schedule(deadline: .now(), repeating: .milliseconds(5), leeway: .milliseconds(1))
                    timer.setEventHandler { [weak self] in self?.pump() }
                    self.timer = timer; timer.resume()
                    self.startup = completionHandler; self.startTime = Date()
                }
            }
        }
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        work.async {self.cleanup();completionHandler()}
    }
    private func cleanup() {
        if let callback = startup { startup = nil; callback(failure("UDP startup cancelled")) }
        timer?.cancel();timer=nil;monitor.cancel()
        scanner.cancel(); lastPump = nil
        for id in Array(flows.keys) {close(id)}
        if let engine {verz_destroy(engine)}
        engine=nil
    }
    private func failure(_ message: String) -> NSError {NSError(domain:"com.verz.link.proxy",code:1,userInfo:[NSLocalizedDescriptionKey:message])}
    private func valid(_ endpoint: NWHostEndpoint) -> Bool {
        var address = in_addr()
        return endpoint.hostname != gatewayHost && inet_pton(AF_INET, endpoint.hostname, &address) == 1
            && UInt16(endpoint.port).map { $0 > 0 } == true
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {false}
    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        guard let endpoint = remoteEndpoint as? NWHostEndpoint,
              valid(endpoint) else {return false}
        work.async {
            guard self.engine != nil, self.flows.count < 256, self.nextFlow <= UInt16.max else {
                flow.closeReadWithError(self.failure("Streaming flow capacity reached"));flow.closeWriteWithError(nil);return
            }
            // Synthetic IDs avoid collisions between different processes using the same local port.
            // Never reuse an ID within an engine session.
            let id = UInt16(self.nextFlow);self.nextFlow += 1;self.flows[id] = flow
            flow.open(withLocalEndpoint: nil) { error in
                self.work.async {if error != nil {self.close(id)} else {self.read(id)}}
            }
        }
        return true
    }
    private func close(_ id: UInt16) {
        guard let flow = flows.removeValue(forKey:id) else {return}
        pendingWrites.removeValue(forKey:id)
        flow.closeReadWithError(nil);flow.closeWriteWithError(nil)
    }
    private func read(_ id: UInt16) {
        guard let flow = flows[id] else {return}
        flow.readDatagrams { data, endpoints, error in
            self.work.async {
                guard self.flows[id] != nil, let engine = self.engine,
                      error == nil, let data, let endpoints, !data.isEmpty, data.count == endpoints.count else {self.close(id);return}
                for (datagram, endpoint) in zip(data,endpoints) {
                    guard let endpoint = endpoint as? NWHostEndpoint, self.valid(endpoint), let port = UInt16(endpoint.port) else {continue}
                    var address = in_addr()
                    guard inet_pton(AF_INET, endpoint.hostname, &address) == 1 else {continue}
                    let result = datagram.withUnsafeBytes {
                        verz_send(engine,id,UInt32(bigEndian:address.s_addr),port,$0.bindMemory(to:UInt8.self).baseAddress,datagram.count)
                    }
                    if result != 0 { self.localDrops += 1 }
                    else { self.payloadSent += UInt64(datagram.count) }
                }
                self.read(id)
            }
        }
    }
    private func pump() {
        guard let engine else {return}
        let now = DispatchTime.now().uptimeNanoseconds
        if let last = lastPump {
            let gap = Double(now - last) / 1_000_000
            maxPumpGapMS = max(maxPumpGapMS, gap)
            if gap > 100 { NSLog("VERZ UDP packet queue gap %.1f ms", gap) }
        }
        lastPump = now
        verz_tick(engine); ticks += 1
        if let callback = startup {
            var status = [UInt8](repeating: 0, count: 65536)
            let n = verz_status(engine, &status, status.count)
            let object = (try? JSONSerialization.jsonObject(with: Data(status.prefix(n)))) as? [String: Any]
            let ready = (object?["paths"] as? [[String: Any]])?.contains { ($0["status"] as? Int) == 1 } ?? false
            if ready { startup = nil; callback(nil) }
            else if Date().timeIntervalSince(startTime) > 10 {
                startup = nil; cleanup(); callback(failure("Encrypted UDP gateway did not authenticate on any adapter.")); return
            }
        }
        if ticks % 40 == 0 {scan()}
        var buffer = [UInt8](repeating:0,count:16392)
        for _ in 0..<256 {
            let n = verz_receive(engine,&buffer,buffer.count)
            if n < 8 {break}
            let id = UInt16(buffer[0]) << 8 | UInt16(buffer[1])
            guard let flow = flows[id], pendingWrites[id,default:0] < 64 else { localDrops += 1; continue }
            let address = buffer[2..<6].map(String.init).joined(separator:".")
            let port = UInt16(buffer[6]) << 8 | UInt16(buffer[7])
            guard valid(NWHostEndpoint(hostname: address, port: String(port))) else { localDrops += 1; continue }
            pendingWrites[id,default:0] += 1
            let payloadBytes = UInt64(n - 8)
            let payloadSource = self.payloadSource
            flow.writeDatagrams([Data(buffer[8..<n])], sentBy:[NWHostEndpoint(hostname:address,port:String(port))]) {error in
                self.work.async {
                    if error == nil && self.payloadSource == payloadSource { self.payloadReceived += payloadBytes }
                    guard self.flows[id] != nil else {return}
                    self.pendingWrites[id,default:1] -= 1
                    if error != nil {self.close(id)}
                }
            }
        }
    }
    private func scan() {
        guard engine != nil else { return }
        scanner.request { [weak self] snapshot, elapsed in
            guard let self, let engine = self.engine else { return }
            self.maxInventoryMS = max(self.maxInventoryMS, elapsed)
            if elapsed > 100 { NSLog("VERZ UDP background inventory took %.1f ms", elapsed) }
            // A failed OS query is not evidence that every WAN disappeared.
            guard let snapshot else { return }
            var rows: [[String: Any]] = []
            for adapter in snapshot where !self.disabled.contains(adapter.name) {
                if self.ids[adapter.name] == nil {
                    guard self.nextID <= 255 else { continue }
                    self.ids[adapter.name] = UInt8(self.nextID); self.nextID += 1
                }
                rows.append(["id": Int(self.ids[adapter.name]!), "name": adapter.name, "address": adapter.address])
            }
            if let data = try? JSONSerialization.data(withJSONObject: rows) {
                let start = DispatchTime.now().uptimeNanoseconds
                _ = data.withUnsafeBytes { verz_adapters(engine, $0.bindMemory(to: UInt8.self).baseAddress, data.count) }
                let duration = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
                self.maxAdapterApplyMS = max(self.maxAdapterApplyMS, duration)
                if duration > 100 { NSLog("VERZ UDP adapter update took %.1f ms", duration) }
            }
        }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        work.async {
            guard let engine=self.engine else {completionHandler?(nil);return}
            if let settings = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any] {
                if let names = settings["disabled"] as? [String] { self.disabled = Set(names); self.scan() }
                if let mode = settings["mode"] as? Int { verz_mode(engine, Int32(mode)) }
            }
            var buffer=[UInt8](repeating:0,count:65536)
            let n=verz_status(engine,&buffer,buffer.count)
            var status = (try? JSONSerialization.jsonObject(with: Data(buffer.prefix(n)))) as? [String: Any] ?? [:]
            status["provider_drops"] = self.localDrops
            status["pump_max_gap_ms"] = self.maxPumpGapMS
            status["inventory_max_ms"] = self.maxInventoryMS
            status["adapter_apply_max_ms"] = self.maxAdapterApplyMS
            status["payload"] = ["version":1, "source_id":self.payloadSource,
                "sampled_at_ms":UInt64((ProcessInfo.processInfo.systemUptime - self.payloadEpoch) * 1000),
                "upload_bytes":self.payloadSent, "download_bytes":self.payloadReceived,
                "unmeasured_packets":0, "basis":"udp_datagrams"] as [String: Any]
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))
        }
    }
}
