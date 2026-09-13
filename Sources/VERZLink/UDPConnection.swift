import AppKit
import Foundation
@preconcurrency import NetworkExtension
import SystemExtensions

/// Owns the repo-style UDP provider independently of the TCP tunnel helper.
@MainActor
final class UDPConnection: NSObject, @preconcurrency OSSystemExtensionRequestDelegate {
    static let identifier = "com.omaralabed.verzlink.classic.udp"
    private var manager: NETransparentProxyManager?
    private var activation: OSSystemExtensionRequest?
    private var generation = UUID()
    private var observer: NSObjectProtocol?
    private var configuration: [String: Any] = [:]
    private var key: String?
    private var completion: ((Result<Void, Error>) -> Void)?
    var onMessage: ((String) -> Void)?
    var onFailure: ((String) -> Void)?
    var onTelemetry: ((Data) -> Void)?
    private var starting = false
    private var stopping = false
    private var requestedStart = false
    private var observedConnecting = false
    private var startupTimeout: DispatchWorkItem?

    override init() {
        super.init()
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            Task { @MainActor in self?.statusChanged(note.object) }
        }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    private func failure(_ text: String) -> Error { NSError(domain: "VERZ UDP", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
    func connect(host: String, key: String, disabled: [String], policy: String, completion: @escaping (Result<Void, Error>) -> Void) {
        disconnect()
        generation = UUID(); stopping = false; starting = true
        self.key = key; self.completion = completion
        configuration = ["gateway": "\(host):4443", "session": Int(UInt32.random(in: 1...UInt32.max)),
                         "disabled": disabled, "mode": mode(policy)]
        guard Bundle.main.bundleURL.path.hasPrefix("/Applications/") else {
            finish(.failure(failure("Install this build in /Applications before enabling the UDP extension."))); return
        }
        let current = generation
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            Task { @MainActor in
                guard self.generation == current, self.starting else { return }
                if let error { self.finish(.failure(error)); return }
                self.manager = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.identifier }
                let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.identifier, queue: .main)
                self.activation = request; request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
            }
        }
    }
    func disconnect() {
        generation = UUID(); activation = nil; completion = nil; key = nil; starting = false; stopping = true
        requestedStart = false; observedConnecting = false; startupTimeout?.cancel(); startupTimeout = nil
        manager?.connection.stopVPNTunnel()
    }
    private func finish(_ result: Result<Void, Error>) {
        let callback = completion; completion = nil; key = nil; starting = false
        requestedStart = false; startupTimeout?.cancel(); startupTimeout = nil
        if case .failure = result { stopping = true; manager?.connection.stopVPNTunnel() }
        callback?(result)
    }
    private func statusChanged(_ object: Any?) {
        guard let manager, let connection = object as? NEVPNConnection, connection === manager.connection else { return }
        switch connection.status {
        case .connecting, .reasserting:
            if starting && requestedStart { observedConnecting = true }
        case .connected:
            if starting { finish(.success(())) }
        case .invalid, .disconnected:
            if starting && requestedStart {
                let current = generation
                connection.fetchLastDisconnectError { [weak self] error in
                    Task { @MainActor in
                        guard let self, self.generation == current, self.starting, self.requestedStart,
                              connection.status == .disconnected || connection.status == .invalid else { return }
                        // A preferences refresh can emit the old disconnected state before
                        // startup. Do not treat that notification alone as a failed start.
                        guard error != nil || self.observedConnecting else { return }
                        let detail = error?.localizedDescription ?? "The provider stopped before startup completed."
                        self.finish(.failure(self.failure("UDP extension could not start: \(detail)")))
                    }
                }
                return
            }
            if !stopping && !starting { onFailure?("The independent UDP provider stopped. Disconnecting VERZ to restore normal networking.") }
        default: break
        }
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard request === activation else { return }
        onMessage?("Enable VERZ Link UDP in Network Extensions. Connection will continue after macOS approval.")
        let alert = NSAlert()
        alert.messageText = "Allow VERZ Link UDP"
        alert.informativeText = "macOS needs your approval once. Open System Settings, enable VERZ Link UDP under Network Extensions, then return here."
        alert.addButton(withTitle: "Open System Settings"); alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            if let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.network_extension") { NSWorkspace.shared.open(url) }
        } else { finish(.failure(failure("UDP setup cancelled"))); activation = nil }
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard request === activation else { return }; activation = nil; finish(.failure(error))
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard request === activation, starting else { return }; activation = nil
        guard result == .completed else { finish(.failure(failure("Restart macOS to complete UDP extension installation."))); return }
        let manager = self.manager ?? NETransparentProxyManager(); self.manager = manager
        let proto = NETunnelProviderProtocol(); proto.providerBundleIdentifier = Self.identifier
        proto.serverAddress = configuration["gateway"] as? String; proto.providerConfiguration = configuration
        manager.protocolConfiguration = proto; manager.localizedDescription = "VERZ Link UDP"; manager.isEnabled = true
        let current = generation
        manager.saveToPreferences { error in
            Task { @MainActor in
                guard self.generation == current, self.starting else { return }
                if let error { self.finish(.failure(error)); return }
                manager.loadFromPreferences { error in
                    Task { @MainActor in
                        guard self.generation == current, self.starting else { return }
                        if let error { self.finish(.failure(error)); return }
                        guard let key = self.key else { return }
                        do {
                            self.requestedStart = true
                            self.observedConnecting = false
                            try manager.connection.startVPNTunnel(options: ["key": key as NSString])
                            let timeout = DispatchWorkItem { [weak self] in
                                guard let self, self.generation == current, self.starting else { return }
                                self.finish(.failure(self.failure("UDP extension startup timed out. Normal networking has been restored.")))
                            }
                            self.startupTimeout = timeout
                            DispatchQueue.main.asyncAfter(deadline: .now() + 20, execute: timeout)
                        }
                        catch { self.finish(.failure(error)) }
                    }
                }
            }
        }
    }
    private func mode(_ policy: String) -> Int { policy == "performance" ? 1 : policy == "data-saver" ? 3 : 2 }
    func update(disabled: [String], policy: String) {
        guard let session = manager?.connection as? NETunnelProviderSession, session.status == .connected,
              let data = try? JSONSerialization.data(withJSONObject: ["disabled": disabled, "mode": mode(policy)]) else { return }
        try? session.sendProviderMessage(data) { _ in }
    }
    func telemetry() {
        guard let session = manager?.connection as? NETunnelProviderSession, session.status == .connected else { return }
        let current = generation
        try? session.sendProviderMessage(Data("status".utf8)) { [weak self] data in
            Task { @MainActor in
                guard let self, self.generation == current, !self.stopping else { return }
                if let data { self.onTelemetry?(data) }
            }
        }
    }
}
