import XCTest
import NetworkExtension
@testable import VERZLink

final class UDPCaptureRulesTests: XCTestCase {
    private func ipv4(_ text: String) -> UInt32 {
        text.split(separator: ".").reduce(0) { ($0 << 8) | UInt32($1)! }
    }

    func testIncludedRangesCoverOnlyUnicastSpaceWithoutGapsOrOverlaps() {
        var next: UInt64 = 0x01000000
        for range in UDPCaptureRules.included {
            let start = UInt64(ipv4(range.address))
            let size = UInt64(1) << (32 - range.prefix)
            XCTAssertEqual(start, next)
            XCTAssertEqual(start % size, 0)
            next = start + size
        }
        XCTAssertEqual(next, 0xe0000000) // Exclude all of 224/3 and 0/8.
    }

    func testActualProviderRulesMeetTransparentProxyRequirements() throws {
        let settings = UDPCaptureRules.settings(gateway: "69.164.213.57")
        let included = try XCTUnwrap(settings.includedNetworkRules)
        let excluded = try XCTUnwrap(settings.excludedNetworkRules)
        XCTAssertEqual(included.count, 9)
        XCTAssertEqual(excluded.count, 6)
        for rule in included + excluded {
            let endpoint = try XCTUnwrap(rule.matchRemoteEndpoint)
            XCTAssertNotEqual(endpoint.hostname, "0.0.0.0")
            XCTAssertEqual(endpoint.port, "0")
            XCTAssertNil(rule.matchLocalNetwork)
            XCTAssertEqual(rule.matchProtocol, .UDP)
            XCTAssertEqual(rule.matchDirection, .outbound)
        }
        XCTAssertEqual(excluded.first?.matchRemoteEndpoint?.hostname, "69.164.213.57")
        XCTAssertEqual(excluded.first?.matchRemotePrefix, 32)
    }

    func testLocalDestinationsRemainExcluded() {
        for address in ["10.1.2.3", "127.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.2"] {
            XCTAssertTrue(UDPCaptureRules.excluded.contains {
                let mask = UInt32.max << (32 - $0.prefix)
                return ipv4(address) & mask == ipv4($0.address)
            }, address)
        }
    }
}
