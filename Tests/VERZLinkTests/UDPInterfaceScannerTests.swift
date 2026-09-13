import XCTest
@testable import VERZLink

final class UDPInterfaceScannerTests: XCTestCase {
    func testBlockedInventoryDoesNotBlockPacketOwnerAndCoalescesRequests() {
        let owner = DispatchQueue(label: "test.udp.packet-owner")
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let returned = expectation(description: "Inventory result")
        let packetWork = expectation(description: "Packet owner remains responsive")
        let scanner = UDPInterfaceScanner(owner: owner) {
            entered.signal()
            _ = release.wait(timeout: .now() + 5)
            return [UDPAdapterAddress(name: "en0", address: "192.0.2.1")]
        }
        owner.async {
            scanner.request { rows, _ in
                XCTAssertEqual(rows, [UDPAdapterAddress(name: "en0", address: "192.0.2.1")])
                returned.fulfill()
            }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        owner.async {
            for _ in 0..<100 {
                scanner.request { _, _ in XCTFail("Hot-plug burst must not queue more scans") }
            }
            packetWork.fulfill()
        }
        // Inventory is still blocked here. Forwarding work must run anyway.
        wait(for: [packetWork], timeout: 1)
        release.signal()
        wait(for: [returned], timeout: 1)
        XCTAssertEqual(entered.wait(timeout: .now()), .timedOut)
    }

    func testCancelledInventoryCannotApplyToRestartedEngine() {
        let owner = DispatchQueue(label: "test.udp.restart-owner")
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let current = expectation(description: "New generation inventory")
        let scanner = UDPInterfaceScanner(owner: owner) {
            entered.signal()
            _ = release.wait(timeout: .now() + 5)
            return []
        }
        owner.async { scanner.request { _, _ in XCTFail("Cancelled result applied") } }
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        owner.sync {
            scanner.cancel()
            scanner.request { rows, _ in
                XCTAssertEqual(rows, [])
                current.fulfill()
            }
        }
        release.signal()
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        release.signal()
        wait(for: [current], timeout: 1)
    }

    func testInventoryFailureIsNotAnEmptyWANList() {
        let owner = DispatchQueue(label: "test.udp.failed-inventory")
        let delivered = expectation(description: "Failed scan delivered as nil")
        let scanner = UDPInterfaceScanner(owner: owner, read: { nil })
        owner.async {
            scanner.request { rows, _ in
                XCTAssertNil(rows)
                delivered.fulfill()
            }
        }
        wait(for: [delivered], timeout: 1)
    }
}
