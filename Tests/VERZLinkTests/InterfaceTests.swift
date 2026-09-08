import XCTest
@testable import VERZLink

final class InterfaceTests: XCTestCase {
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
    func testSelfAssignedIPv4IsNotAUsableRelayPath() {
        XCTAssertFalse(ethernet(addresses: ["169.254.2.3"]).canConnect)
        XCTAssertFalse(LinkInterface.usableIPv4("127.0.0.1"))
        XCTAssertFalse(LinkInterface.usableIPv4("0.0.0.0"))
        XCTAssertTrue(ethernet().canConnect)
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
