import XCTest
@testable import VERZLink

final class NetworkTestTests: XCTestCase {
    func testRawCommandFailureIsNeverShownToCustomer() {
        let raw = LinkError.message("curl: (7) Failed to connect to 10.78.0.1 port 8080")
        let message = NetworkTest.userFacingMessage(for: raw)

        XCTAssertEqual(message, "Diagnostics could not complete. Check your VERZ connection and try again.")
        XCTAssertFalse(message.localizedCaseInsensitiveContains("curl"))
        XCTAssertFalse(message.contains("10.78.0.1"))
        XCTAssertFalse(message.contains("8080"))
    }

    func testKnownDiagnosticsFailureUsesSafeCustomerMessage() {
        let message = NetworkTest.userFacingMessage(for: NetworkTestError.protectedServiceUnavailable)

        XCTAssertEqual(message, "The protected diagnostics service is temporarily unavailable. Please try again.")
        XCTAssertFalse(message.localizedCaseInsensitiveContains("curl"))
        XCTAssertFalse(message.contains("10.78.0.1"))
        XCTAssertFalse(message.contains("8080"))
    }
}
