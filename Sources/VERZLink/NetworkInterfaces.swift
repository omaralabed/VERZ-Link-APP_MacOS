import Foundation
import Darwin
import SystemConfiguration

struct LinkInterface: Identifiable, Hashable, Sendable {
    let name: String
    let displayName: String
    let isWiFi: Bool
    let addresses: [String]
    let isUp: Bool
    let linkActive: Bool?
    var id: String { name }
    var address: String? { addresses.first(where: Self.usableIPv4) }
    var canConnect: Bool { isUp && linkActive != false && address != nil }
    var title: String { "\(displayName) (\(name))" }
    var status: String {
        if !isUp { return "Disabled" }
        if linkActive == false { return isWiFi ? "Not connected" : "No cable link" }
        if canConnect { return "Ready" }
        if addresses.contains(where: { $0.hasPrefix("169.254.") }) { return "Self-assigned IPv4 · check DHCP" }
        return "Waiting for IPv4 address"
    }

    static func usableIPv4(_ text: String) -> Bool {
        let octets = text.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4, octets[0] > 0, octets[0] < 224, octets[0] != 127 else { return false }
        return !(octets[0] == 169 && octets[1] == 254)
    }
}

enum InterfaceInventory {
    static func selectedName(current: String, busy: Bool, interfaces: [LinkInterface]) -> String {
        // Do not silently change the displayed uplink of a running tunnel.
        if busy || interfaces.contains(where: { $0.name == current && $0.canConnect }) { return current }
        return interfaces.first(where: \.canConnect)?.name ?? current
    }

    static func snapshot() -> [LinkInterface] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return [] }
        defer { freeifaddrs(list) }
        var cursor = list
        var flags: [String: UInt32] = [:]
        var addresses: [String: [String]] = [:]
        while let pointer = cursor {
            let item = pointer.pointee
            defer { cursor = item.ifa_next }
            let name = String(cString: item.ifa_name)
            flags[name] = item.ifa_flags
            guard let address = item.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            let ipv4 = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            addresses[name, default: []].append(String(cString: inet_ntoa(ipv4)))
        }
        let store = SCDynamicStoreCreate(nil, "VERZ Link interface inventory" as CFString, nil, nil)
        let hardware = SCNetworkInterfaceCopyAll() as! [SCNetworkInterface]
        var result: [String: LinkInterface] = [:]
        for item in hardware {
            guard let bsdName = SCNetworkInterfaceGetBSDName(item) else { continue }
            let name = bsdName as String
            guard let interfaceFlags = flags[name] else { continue } // Adapter is physically present.
            let type = SCNetworkInterfaceGetInterfaceType(item)
            let isWiFi = type == kSCNetworkInterfaceTypeIEEE80211
            guard isWiFi || type == kSCNetworkInterfaceTypeEthernet || name.hasPrefix("bridge") else { continue }
            let link = store.flatMap { SCDynamicStoreCopyValue($0, "State:/Network/Interface/\(name)/Link" as CFString) as? [String: Any] }
            let displayName = SCNetworkInterfaceGetLocalizedDisplayName(item).map { $0 as String }
                ?? (isWiFi ? "Wi-Fi" : "Ethernet")
            result[name] = LinkInterface(name: name, displayName: displayName, isWiFi: isWiFi,
                addresses: Array(Set(addresses[name] ?? [])).sorted(),
                isUp: interfaceFlags & UInt32(IFF_UP) != 0, linkActive: link?[kSCPropNetLinkActive as String] as? Bool)
        }
        return result.values.sorted {
            if $0.canConnect != $1.canConnect { return $0.canConnect }
            if $0.isWiFi != $1.isWiFi { return $0.isWiFi }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }
}

/// Re-enumerate every two seconds, including when the default path does not
/// change (e.g. plugging Ethernet in while Wi-Fi remains connected).
final class InterfaceMonitor {
    private let timer: DispatchSourceTimer
    init(update: @escaping @Sendable ([LinkInterface]) -> Void) {
        timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "com.verz.link.interfaces", qos: .utility))
        timer.schedule(deadline: .now(), repeating: .seconds(2), leeway: .milliseconds(150))
        timer.setEventHandler { update(InterfaceInventory.snapshot()) }
        timer.resume()
    }
    deinit { timer.cancel() }
}
