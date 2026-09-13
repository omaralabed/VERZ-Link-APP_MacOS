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
    // nil: static/unknown configuration. false: DHCP still provisional
    // (INIT-REBOOT/SELECT); macOS withdraws such an address seconds later.
    var dhcpConfirmed: Bool? = nil
    var id: String { name }
    var address: String? { addresses.first(where: Self.usableIPv4) }
    var canConnect: Bool { isUp && linkActive != false && address != nil && dhcpConfirmed != false }
    // Carrier can be up before DHCP completes; that adapter stays visible.
    var isConnected: Bool { isUp && (linkActive ?? (address != nil)) }
    var title: String { displayName.contains("(\(name))") ? displayName : "\(displayName) (\(name))" }
    var status: String {
        if !isUp { return "Disabled" }
        if linkActive == false { return isWiFi ? "Not connected" : "No cable link" }
        if canConnect { return "Ready" }
        if address != nil && dhcpConfirmed == false { return "Confirming DHCP lease" }
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
    static func carrierState(flags: UInt32, mediaActive: Bool?) -> Bool? {
        // Match the working UDP scanner: stale DHCP/media state must not keep
        // a physically stopped adapter in the TCP engine configuration.
        guard flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING) else {
            return false
        }
        return mediaActive
    }

    static func selectedName(current: String, busy: Bool, interfaces: [LinkInterface]) -> String {
        // Do not silently change the displayed uplink of a running tunnel.
        if busy || interfaces.contains(where: { $0.name == current && $0.canConnect }) { return current }
        return interfaces.first(where: \.canConnect)?.name ?? current
    }

    /// Parses `ipconfig getsummary` output. nil when IPv4 is not DHCP-managed.
    static func dhcpConfirmed(summary: String) -> Bool? {
        let lines = summary.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.contains("ConfigMethod : DHCP") else { return nil }
        guard let state = lines.first(where: { $0.hasPrefix("State : ") })?.dropFirst("State : ".count) else { return false }
        return ["BOUND", "RENEW", "REBIND"].contains(String(state))
    }

    private static func dhcpConfirmed(interface: String) -> Bool? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/ipconfig")
        task.arguments = ["getsummary", interface]
        let output = Pipe()
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        guard (try? task.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else { return nil }
        return dhcpConfirmed(summary: text)
    }

    private static let leaseLock = NSLock()
    private static var leaseCache: [String: (addresses: [String], confirmed: Bool?)] = [:]
    // A confirmed lease is re-queried only when the address set changes; a
    // provisional one is re-checked on every snapshot until it is bound.
    private static func cachedDHCPConfirmed(interface: String, addresses: [String]) -> Bool? {
        leaseLock.lock()
        let cached = leaseCache[interface]
        leaseLock.unlock()
        if let cached, cached.addresses == addresses, cached.confirmed != false { return cached.confirmed }
        let confirmed = dhcpConfirmed(interface: interface)
        leaseLock.lock()
        leaseCache[interface] = (addresses, confirmed)
        leaseLock.unlock()
        return confirmed
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
            let mediaActive = link?[kSCPropNetLinkActive as String] as? Bool
            var interface = LinkInterface(name: name, displayName: displayName, isWiFi: isWiFi,
                addresses: Array(Set(addresses[name] ?? [])).sorted(),
                isUp: interfaceFlags & UInt32(IFF_UP) != 0,
                linkActive: carrierState(flags: interfaceFlags, mediaActive: mediaActive))
            // Only adapters that already hold a usable address are queried; this
            // runs on the monitor queue, never on the packet path.
            if interface.address != nil {
                interface.dhcpConfirmed = cachedDHCPConfirmed(interface: name, addresses: interface.addresses)
            }
            result[name] = interface
        }
        return result.values.sorted {
            if $0.canConnect != $1.canConnect { return $0.canConnect }
            if $0.isWiFi != $1.isWiFi { return $0.isWiFi }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }
}

private final class InterfaceChangeHandler {
    let update: @Sendable () -> Void
    init(update: @escaping @Sendable () -> Void) { self.update = update }
}

private func interfaceStoreChanged(
    _: SCDynamicStore,
    _: CFArray,
    info: UnsafeMutableRawPointer?
) {
    guard let info else { return }
    Unmanaged<InterfaceChangeHandler>.fromOpaque(info).takeUnretainedValue().update()
}

/// Carrier and IPv4 changes are delivered by SystemConfiguration instead of
/// waiting for a polling interval. The timer is only a safety net for unusual
/// adapters that fail to publish dynamic-store notifications.
final class InterfaceMonitor {
    private let queue: DispatchQueue
    private let handler: InterfaceChangeHandler
    private let store: SCDynamicStore?
    private let timer: DispatchSourceTimer
    init(update: @escaping @Sendable ([LinkInterface]) -> Void) {
        let queue = DispatchQueue(label: "com.verz.link.interfaces", qos: .userInitiated)
        self.queue = queue
        handler = InterfaceChangeHandler { update(InterfaceInventory.snapshot()) }
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(handler).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let store = SCDynamicStoreCreate(
            nil,
            "VERZ Link carrier monitor" as CFString,
            interfaceStoreChanged,
            &context
        )
        if let store {
            let patterns = [
                "State:/Network/Interface/.*/Link",
                "State:/Network/Interface/.*/IPv4"
            ] as CFArray
            if !SCDynamicStoreSetNotificationKeys(store, nil, patterns)
                || !SCDynamicStoreSetDispatchQueue(store, queue) {
                SCDynamicStoreSetDispatchQueue(store, nil)
            }
        }
        self.store = store
        timer = DispatchSource.makeTimerSource(queue: queue)
        // The UDP engine rescans every 200 ms. Use the same safety interval so
        // a driver that omits a dynamic-store event cannot leave TCP on a dead
        // adapter for a full second.
        timer.schedule(deadline: .now() + .milliseconds(200), repeating: .milliseconds(200), leeway: .milliseconds(20))
        timer.setEventHandler { update(InterfaceInventory.snapshot()) }
        timer.resume()
        queue.async { update(InterfaceInventory.snapshot()) }
    }
    deinit {
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
        timer.cancel()
    }
}
