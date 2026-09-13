import XCTest
@testable import VERZLink

final class PayloadTrafficTests: XCTestCase {
    private func report(_ ms: UInt64, _ up: UInt64, _ down: UInt64, source: String = "a",
                        missed: UInt64 = 0, basis: String = "tcp_socket_payload") -> PayloadTelemetry {
        PayloadTelemetry(version: 1, sourceId: source, sampledAtMs: ms,
                         uploadBytes: up, downloadBytes: down, unmeasuredPackets: missed, basis: basis)
    }
    func testRatesUseProducerTimeNotBunchedUICallbacks() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 0, 0), at: 10)
        meter.receive(report(2000, 1_000_000, 10_000_000), at: 10.001)
        XCTAssertEqual(meter.rate(at: 10.002)!.up, 8, accuracy: 0.0001)
        XCTAssertEqual(meter.rate(at: 10.002)!.down, 80, accuracy: 0.0001)
    }
    func testNoFirstSampleSpikeAndTotalsIncludeStartupBytes() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 5_000_000, 9_000_000), at: 1)
        XCTAssertNil(meter.rate(at: 1))
        XCTAssertEqual(meter.uploaded, 5_000_000)
        meter.receive(report(2000, 5_000_000, 9_000_000), at: 2)
        XCTAssertEqual(meter.rate(at: 2)!.up, 0)
    }
    func testThreeSecondRollingRateSettlesToRealZero() {
        var meter = PayloadRateTracker()
        for second in 0...3 { meter.receive(report(UInt64(second * 1000), UInt64(second * 1_000_000), 0), at: Double(second)) }
        XCTAssertEqual(meter.rate(at: 3)!.up, 8)
        for second in 4...6 { meter.receive(report(UInt64(second * 1000), 3_000_000, 0), at: Double(second)) }
        XCTAssertEqual(meter.rate(at: 6)!.up, 0)
    }
    func testStaleDuplicateAndOutOfOrderReportsDoNotRefreshSpeed() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 0, 0), at: 1)
        meter.receive(report(2000, 1_000_000, 0), at: 2)
        meter.receive(report(2000, 9_000_000, 0), at: 4)
        meter.receive(report(1500, 8_000_000, 0), at: 4)
        XCTAssertNil(meter.rate(at: 5))
        XCTAssertEqual(meter.uploaded, 1_000_000)
    }
    func testRestartPreservesTotalsButRequiresFreshRateBaseline() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 100, 200), at: 1)
        meter.receive(report(2000, 200, 400), at: 2)
        meter.receive(report(500, 50, 70, source: "b"), at: 3)
        XCTAssertNil(meter.rate(at: 3))
        XCTAssertEqual(meter.uploaded, 250)
        meter.receive(report(3000, 5000, 9000), at: 4) // late old producer
        XCTAssertEqual(meter.uploaded, 250)
        meter.receive(report(1500, 100, 90, source: "b"), at: 4)
        XCTAssertEqual(meter.uploaded, 300)
    }
    func testUnannouncedResetAndCoverageLossAreNotCalledComplete() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 100, 200), at: 1)
        meter.receive(report(2000, 50, 50), at: 2)
        XCTAssertEqual(meter.uploaded, 100); XCTAssertTrue(meter.partial)
        var limited = PayloadRateTracker()
        limited.receive(report(1000, 100, 200, missed: 1), at: 1)
        XCTAssertTrue(limited.incompleteTotals)
    }
    func testLongGapDoesNotBecomeAnInstantaneousSpike() {
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 100, 200), at: 1)
        meter.receive(report(7000, 6_000_100, 200), at: 7)
        XCTAssertNil(meter.rate(at: 7))
        XCTAssertEqual(meter.uploaded, 6_000_100)
        meter.receive(report(8000, 7_000_100, 200), at: 8)
        XCTAssertEqual(meter.rate(at: 8)!.up, 8)
    }
    func testMissingTelemetryDoesNotFallBackToInterfaceTraffic() {
        let meter = PayloadTraffic()
        XCTAssertNil(meter.summary(mode: .secure, at: 1).down)
        let legacy = #"{"paths":[],"healthy_paths":1,"assigned_ip":"","server_ip":""}"#
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        XCTAssertNil(try decoder.decode(BondTelemetry.self, from: Data(legacy.utf8)).payload)
    }
    func testModesCombineOnlyTheirDistinctPayloadSources() {
        var meter = PayloadTraffic()
        for (source, amount) in [(PayloadTraffic.Source.tunnel, 1_000_000), (.direct, 2_000_000), (.udp, 3_000_000)] {
            meter.receive(report(0, 0, 0), from: source, at: 0)
            meter.receive(report(1000, UInt64(amount), 0), from: source, at: 1)
        }
        XCTAssertEqual(meter.summary(mode: .secure, at: 1).up, 32)
        XCTAssertEqual(meter.summary(mode: .direct, at: 1).up, 16)
        XCTAssertEqual(meter.summary(mode: .hybrid, at: 1).up, 48)
        XCTAssertEqual(meter.summary(mode: .hybrid, at: 1).uploaded, 6_000_000)
    }
    func testOneMissingProducerMakesCombinedRateUnavailable() {
        var meter = PayloadTraffic()
        meter.receive(report(0, 0, 0), from: .tunnel, at: 0)
        meter.receive(report(1000, 1_000_000, 0), from: .tunnel, at: 1)
        XCTAssertNil(meter.summary(mode: .secure, at: 1).up)
    }
    func testCoverageGapExpiresFromSpeedButNotFromTotalDisclosure() {
        var meter = PayloadRateTracker()
        meter.receive(report(0, 0, 0), at: 0)
        meter.receive(report(1000, 1_000_000, 0, missed: 1), at: 1)
        XCTAssertTrue(meter.partial)
        for second in 2...4 {
            meter.receive(report(UInt64(second * 1000), UInt64(second * 1_000_000), 0, missed: 1), at: Double(second))
        }
        XCTAssertFalse(meter.partial)
        XCTAssertTrue(meter.incompleteTotals)
        XCTAssertEqual(meter.rate(at: 4)!.up, 8)
        XCTAssertEqual(meter.uploaded, 4_000_000)
    }
    func testUDPProviderEnvelopeDecodesUniqueDatagramCounters() throws {
        let data = Data(#"{"payload":{"version":1,"source_id":"udp-1","sampled_at_ms":2000,"upload_bytes":750000,"download_bytes":250000,"unmeasured_packets":0,"basis":"udp_datagrams"}}"#.utf8)
        let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
        let payload = try XCTUnwrap(decoder.decode(UDPProviderTelemetry.self, from: data).payload)
        var meter = PayloadRateTracker()
        meter.receive(report(1000, 0, 0, source: "udp-1", basis: "udp_datagrams"), at: 1)
        meter.receive(payload, at: 2)
        XCTAssertEqual(meter.rate(at: 2)!.up, 6, accuracy: 0.0001)
        XCTAssertEqual(meter.rate(at: 2)!.down, 2, accuracy: 0.0001)
        XCTAssertEqual(meter.uploaded, 750_000)
        XCTAssertEqual(meter.downloaded, 250_000)
    }
}
