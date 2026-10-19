import XCTest
import Darwin
@testable import VERZLink

final class InterfaceTests: XCTestCase {
    func testCustomerConnectionPresetsExposeOnlySupportedOutcomes() {
        XCTAssertEqual(ConnectionPreset.allCases, [.bonded, .smart, .continuity, .direct])
        XCTAssertEqual(ConnectionPreset.bonded.settings.mode, .secure)
        XCTAssertEqual(ConnectionPreset.bonded.settings.policy, "performance")
        XCTAssertEqual(ConnectionPreset.smart.settings.mode, .secure)
        XCTAssertEqual(ConnectionPreset.smart.settings.policy, "smart-repair")
        XCTAssertEqual(ConnectionPreset.continuity.settings.policy, "continuity")
        XCTAssertEqual(ConnectionPreset.direct.settings.mode, .direct)
        XCTAssertEqual(ConnectionPreset.matching(mode: .secure, policy: "smart-repair"), .smart)
        XCTAssertEqual(ConnectionPreset.matching(mode: .direct, policy: "smart-repair"), .direct)
    }

    func testEveryPresetHandsTheHelperAPolicyItAccepts() {
        // Mirrors the list in HelperService/main.swift.
        let accepted: Set<String> = ["smart", "performance", "continuity", "data-saver"]
        for preset in ConnectionPreset.allCases {
            XCTAssertTrue(accepted.contains(mainTunnelPolicy(preset.settings.policy)), "\(preset) hands the helper \(preset.settings.policy)")
        }
        XCTAssertEqual(mainTunnelPolicy("smart-repair"), "performance")
        XCTAssertEqual(mainTunnelPolicy("continuity"), "continuity")
    }

    func testSmartRepairSettingsSurviveNormalization() {
        XCTAssertEqual(normalizedConnectionSettings(mode: .secure, policy: "smart-repair", avoidMeteredLinks: false),
                       NormalizedConnectionSettings(mode: .secure, policy: "smart-repair", avoidMeteredLinks: false))
        XCTAssertEqual(normalizedConnectionSettings(mode: .direct, policy: "smart-repair", avoidMeteredLinks: true),
                       NormalizedConnectionSettings(mode: .direct, policy: "smart", avoidMeteredLinks: true))
    }

    func testLegacyConnectionSettingsMigrateWithoutAdaptiveDuplication() {
        XCTAssertEqual(normalizedConnectionSettings(mode: .secure, policy: "adaptive-protection", avoidMeteredLinks: false),
                       NormalizedConnectionSettings(mode: .secure, policy: "performance", avoidMeteredLinks: false))
        XCTAssertEqual(normalizedConnectionSettings(mode: .hybrid, policy: "data-saver", avoidMeteredLinks: false),
                       NormalizedConnectionSettings(mode: .secure, policy: "performance", avoidMeteredLinks: true))
        XCTAssertEqual(normalizedConnectionSettings(mode: .direct, policy: "continuity", avoidMeteredLinks: false),
                       NormalizedConnectionSettings(mode: .direct, policy: "smart", avoidMeteredLinks: false))
    }

    func testAvoidMeteredUsesMeteredPathOnlyWhenNoUnmeteredPathIsUsable() {
        let lan = ethernet("en7")
        let cellular = ethernet("en8")
        XCTAssertEqual(avoidedMeteredInterfaces([lan, cellular], explicitlyDisabled: [],
                                                metered: ["en8"], enabled: true), ["en8"])
        XCTAssertEqual(avoidedMeteredInterfaces([lan, cellular], explicitlyDisabled: ["en7"],
                                                metered: ["en8"], enabled: true), [])
        XCTAssertEqual(avoidedMeteredInterfaces([cellular], explicitlyDisabled: [],
                                                metered: ["en8"], enabled: true), [])
    }

    func testAdaptiveTelemetryAcceptsLiveRatesAndLegacyReports() throws {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let legacy = #"{"id":0,"name":"en0","state":"healthy","enabled":true,"rtt_ms":90,"jitter_ms":2,"sent_bytes":100,"received_bytes":200,"acknowledged_bytes":0,"delivery_bps":0}"#
        let path = try decoder.decode(PathTelemetry.self, from: Data(legacy.utf8))
        XCTAssertNil(path.realtimePreferred)
        XCTAssertNil(path.downloadBps)
        XCTAssertNil(path.uploadHeld)
        XCTAssertNil(path.carrier)
        let current = String(legacy.dropLast()) + #", "carrier":"tls-tcp","standby":true,"realtime_preferred":false,"download_bps":8000000,"upload_bps":2000000,"active_flows":3,"upload_held":true,"tcp_observed":true}"#
        let updated = try decoder.decode(PathTelemetry.self, from: Data(current.utf8))
        XCTAssertEqual(updated.carrier, "tls-tcp")
        XCTAssertEqual(updated.standby, true)
        XCTAssertEqual(updated.realtimePreferred, false)
        XCTAssertEqual(updated.downloadBps, 8_000_000)
        XCTAssertEqual(updated.activeFlows, 3)
        XCTAssertEqual(updated.uploadHeld, true)
        XCTAssertEqual(updated.tcpObserved, true)
    }

    func testBrainReportsMeasuredLearningWithoutRequiringItInLegacyMessages() throws {
        let current = #"{"connected":true,"generation":42,"strategy":"champion-challenger-v7","learnedPaths":2}"#
        XCTAssertEqual(try JSONDecoder().decode(BrainState.self, from: Data(current.utf8)).learnedPaths, 2)
        let legacy = #"{"connected":false,"generation":0,"strategy":"local-fallback"}"#
        XCTAssertNil(try JSONDecoder().decode(BrainState.self, from: Data(legacy.utf8)).learnedPaths)
    }

    func testChampionChallengerTelemetryIsOptionalAndDecodedForEngineering() throws {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let current = #"{"paths":[],"healthy_paths":2,"assigned_ip":"","server_ip":"","traffic_shape":"download","balanced_champion":"en0","download_champion":"en0","upload_champion":"en7","download_guarded":true,"upload_guarded":false}"#
        let report = try decoder.decode(BondTelemetry.self, from: Data(current.utf8))
        XCTAssertEqual(report.trafficShape, "download")
        XCTAssertEqual(report.downloadChampion, "en0")
        XCTAssertEqual(report.uploadChampion, "en7")
        XCTAssertEqual(report.downloadGuarded, true)
        XCTAssertEqual(report.uploadGuarded, false)

        let legacy = #"{"paths":[],"healthy_paths":1,"assigned_ip":"","server_ip":""}"#
        XCTAssertNil(try decoder.decode(BondTelemetry.self, from: Data(legacy.utf8)).trafficShape)
    }

    func testControlSocketBackpressureReturnsWithoutIndefiniteBlocking() {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
        XCTAssertEqual(setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)), 0)
        let start = ProcessInfo.processInfo.systemUptime
        XCTAssertFalse(TunnelSession.writeCommand(Data(repeating: 1, count: 2_000_000), to: pair[0]))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 1.0)
    }
    private func ethernet(_ name: String = "en7", addresses: [String] = ["192.168.108.3"], link: Bool = true) -> LinkInterface {
        LinkInterface(name: name, displayName: "USB Ethernet", isWiFi: false,
                      addresses: addresses, isUp: true, linkActive: link)
    }
    func testEthernetRemainsVisibleWithoutDHCPButCannotCarryIPv4() {
        let port = ethernet(addresses: [])
        XCTAssertEqual(port.title, "USB Ethernet (en7)")
        XCTAssertFalse(port.canConnect)
        XCTAssertEqual(port.status, "Waiting for IPv4 address")
    }
    func testCarrierLossOverridesStaleDHCPAddress() {
        XCTAssertFalse(ethernet(link: false).canConnect)
        XCTAssertEqual(ethernet(link: false).status, "No cable link")
    }
    func testRunningFlagOverridesStalePositiveMediaStateLikeUDPEngine() {
        let upOnly = UInt32(IFF_UP)
        let running = UInt32(IFF_UP | IFF_RUNNING)
        XCTAssertEqual(InterfaceInventory.carrierState(flags: upOnly, mediaActive: true), false)
        XCTAssertEqual(InterfaceInventory.carrierState(flags: running, mediaActive: true), true)
        XCTAssertNil(InterfaceInventory.carrierState(flags: running, mediaActive: nil))
    }
    func testSelfAssignedIPv4IsNotAUsableRelayPath() {
        XCTAssertFalse(ethernet(addresses: ["169.254.2.3"]).canConnect)
        XCTAssertFalse(LinkInterface.usableIPv4("127.0.0.1"))
        XCTAssertFalse(LinkInterface.usableIPv4("0.0.0.0"))
        XCTAssertTrue(ethernet().canConnect)
    }
    func testProvisionalDHCPLeaseIsNotOfferedUntilBound() {
        // Physical replug 2026-09-12: macOS published the INIT-REBOOT address,
        // then withdrew it 4.7 s later when the server never answered.
        let provisional = """
        <dictionary> {
          IPv4 : <array> {
            0 : <dictionary> {
              Addresses : <array> { 0 : 192.168.1.235 }
              ConfigMethod : DHCP
              DHCP : <dictionary> {
                State : INIT-REBOOT
              }
            }
            1 : <dictionary> { ConfigMethod : LinkLocal }
          }
        }
        """
        XCTAssertEqual(InterfaceInventory.dhcpConfirmed(summary: provisional), false)
        XCTAssertEqual(InterfaceInventory.dhcpConfirmed(summary: provisional.replacingOccurrences(of: "INIT-REBOOT", with: "BOUND")), true)
        XCTAssertEqual(InterfaceInventory.dhcpConfirmed(summary: provisional.replacingOccurrences(of: "INIT-REBOOT", with: "RENEW")), true)
        XCTAssertNil(InterfaceInventory.dhcpConfirmed(summary: provisional.replacingOccurrences(of: "ConfigMethod : DHCP", with: "ConfigMethod : Manual")))
        var port = ethernet()
        port.dhcpConfirmed = false
        XCTAssertFalse(port.canConnect)
        XCTAssertTrue(port.isConnected)
        XCTAssertEqual(port.status, "Confirming DHCP lease")
        port.dhcpConfirmed = true
        XCTAssertTrue(port.canConnect)
        port.dhcpConfirmed = nil
        XCTAssertTrue(port.canConnect, "static addressing has no lease to confirm")
    }
    func testOnlyConnectedPortsAreVisibleIncludingDHCPInProgress() {
        XCTAssertFalse(ethernet(link: false).isConnected)
        XCTAssertTrue(ethernet().isConnected)
        XCTAssertTrue(ethernet(addresses: [], link: true).isConnected)
        let ports = (2...21).map { ethernet("en\($0)", link: $0.isMultiple(of: 2)) }
        XCTAssertEqual(ports.filter(\.isConnected).count, 10)
    }
    func testManyAdaptersHaveDistinctIdentities() {
        let ports = (2...21).map { ethernet("en\($0)") }
        XCTAssertEqual(Set(ports.map(\.id)).count, 20)
        XCTAssertTrue(ports.allSatisfy(\.canConnect))
    }
    func testNativeInventoryHasNoTunnelOrLoopbackAdapters() {
        let ports = InterfaceInventory.snapshot()
        XCTAssertEqual(Set(ports.map(\.id)).count, ports.count)
        XCTAssertFalse(ports.contains { $0.name == "lo0" || $0.name.hasPrefix("utun") })
        for port in ports { print("INTERFACE \(port.title) · \(port.status) · \(port.address ?? "no IPv4")") }
    }
}
