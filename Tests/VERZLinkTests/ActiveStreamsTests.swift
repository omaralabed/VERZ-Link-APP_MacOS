import XCTest
@testable import VERZLink

final class ActiveStreamsTests: XCTestCase {
    /// Two delta samples as the tool prints them: lifetime totals first,
    /// then one second of traffic. Only the second may decide.
    private let sample = """
                                                                                      interface        bytes_in       bytes_out
    mDNSResponder.429                                                                                  31645472        14263523
       udp4 *:5353<->*:*                                                                    en0        19651508         9574380
    OBS.60548                                                                                           3680048       535110884
       udp4 *:63690<->*:*                                                                   en7         3680048       535110884
                                                                                      interface        bytes_in       bytes_out
    mDNSResponder.429                                                                                         0            1200
       udp4 *:5353<->*:*                                                                    en0               0            1200
    OBS.60548                                                                                              6400          330000
       udp4 *:63690<->*:*                                                                   en7            6400          330000
    Google Chrome H.54078                                                                                  7186          120000
       tcp4 192.168.78.19:54459<->17.57.144.55:443                                            en0            7186          120000
       udp6 2600:382:ae18::1.52586<->2620:149:a41:280::c.443                                  en0               0          900000
    verz_udp_proxy-.73218                                                                                     0          500000
       udp4 192.168.108.12:58374<->69.164.213.57:4443                                         en7               0          500000
    Finder.900                                                                                                0          800000
       tcp4 10.78.0.2:50000<->1.1.1.1:443                                                   utun4               0          800000

    """

    func testOnlyFastSocketsOnPhysicalLinksInTheLastSampleCount() {
        let streams = ActiveStreams.parse(sample, physical: ["en0", "en7"])
        XCTAssertEqual(streams.map(\.process), ["OBS", "Google Chrome H"])
        let obs = streams[0]
        XCTAssertEqual(obs.pid, 60548)
        XCTAssertEqual(obs.protocolName, "udp")
        XCTAssertEqual(obs.localPort, 63690)
        XCTAssertNil(obs.remote, "an unconnected socket has no known far end")
        XCTAssertEqual(obs.interface, "en7")
        XCTAssertEqual(obs.bytesPerSecond, 330_000)
        XCTAssertEqual(obs.megabitsPerSecond, 2.64, accuracy: 0.001)
        XCTAssertEqual(obs.description, "OBS is sending 2.6 Mbit/s over en7")
        let chrome = streams[1]
        XCTAssertEqual(chrome.protocolName, "tcp")
        XCTAssertEqual(chrome.localPort, 54459)
        XCTAssertEqual(chrome.remote, "17.57.144.55")
    }

    func testNothingIsReportedWithoutASecondSample() {
        XCTAssertEqual(ActiveStreams.parse("", physical: ["en0"]), [])
        let firstOnly = sample.components(separatedBy: "\n").prefix(5).joined(separator: "\n")
        XCTAssertEqual(ActiveStreams.parse(firstOnly, physical: ["en0", "en7"]), [],
                       "the first sample is a lifetime total, not a rate")
    }
}
