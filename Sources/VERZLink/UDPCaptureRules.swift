import NetworkExtension

/// IPv4-only UDP diversion shared by the provider and its regression tests.
/// Transparent proxies reject 0.0.0.0 with port 0 even when a prefix is supplied.
enum UDPCaptureRules {
    static let included: [(address: String, prefix: Int)] = [
        ("1.0.0.0", 8), ("2.0.0.0", 7), ("4.0.0.0", 6),
        ("8.0.0.0", 5), ("16.0.0.0", 4), ("32.0.0.0", 3),
        ("64.0.0.0", 2), ("128.0.0.0", 2), ("192.0.0.0", 3)
    ]
    static let excluded: [(address: String, prefix: Int)] = [
        ("127.0.0.0", 8), ("10.0.0.0", 8), ("172.16.0.0", 12),
        ("192.168.0.0", 16), ("169.254.0.0", 16)
    ]

    static func settings(gateway: String) -> NETransparentProxyNetworkSettings {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: gateway)
        settings.includedNetworkRules = included.map { rule($0.address, $0.prefix) }
        // Keep local traffic and our encrypted transport outside the proxy.
        // 0/8 and multicast/reserved 224/3 are outside the included ranges.
        settings.excludedNetworkRules = ([(gateway, 32)] + excluded).map { rule($0.0, $0.1) }
        return settings
    }

    private static func rule(_ address: String, _ prefix: Int) -> NENetworkRule {
        NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: address, port: "0"), remotePrefix: prefix,
                      localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound)
    }
}
