import Foundation
import SystemConfiguration
import Darwin

struct UDPAdapterAddress: Equatable, Sendable {
    let name: String
    let address: String
}

/// All request/cancel state belongs to the packet queue. Only the potentially
/// blocking OS inventory runs elsewhere; results return to the packet owner.
final class UDPInterfaceScanner: @unchecked Sendable {
    typealias Snapshot = [UDPAdapterAddress]
    private let owner: DispatchQueue
    private let worker = DispatchQueue(label: "com.omaralabed.verzlink.classic.udp.inventory", qos: .utility)
    private let read: @Sendable () -> Snapshot?
    private var generation = UUID()
    private var inFlight = false

    init(owner: DispatchQueue, read: @escaping @Sendable () -> Snapshot? = { UDPInterfaceScanner.snapshot() }) {
        self.owner = owner
        self.read = read
    }

    func request(_ receive: @escaping @Sendable (Snapshot?, Double) -> Void) {
        dispatchPrecondition(condition: .onQueue(owner))
        guard !inFlight else { return } // Coalesce hot-plug notification bursts.
        inFlight = true
        let current = generation
        worker.async { [self] in
            let start = DispatchTime.now().uptimeNanoseconds
            let result = read()
            let milliseconds = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            owner.async { [self] in
                guard generation == current else { return }
                inFlight = false
                receive(result, milliseconds)
            }
        }
    }

    func cancel() {
        dispatchPrecondition(condition: .onQueue(owner))
        generation = UUID()
        inFlight = false
    }

    static func snapshot() -> Snapshot? {
        // Query hardware first: obtain current addresses AFTER that potentially
        // slow SystemConfiguration call, not before a hot-plug transition.
        guard let hardware = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return nil }
        let physical = Set(hardware.compactMap { item -> String? in
            let type = SCNetworkInterfaceGetInterfaceType(item)
            guard type == kSCNetworkInterfaceTypeEthernet || type == kSCNetworkInterfaceTypeIEEE80211 else { return nil }
            return SCNetworkInterfaceGetBSDName(item).map { $0 as String }
        })
        var entries: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&entries) == 0 else { return nil }
        defer { freeifaddrs(entries) }
        var rows: Snapshot = []
        var seen = Set<String>()
        var item = entries
        while let current = item {
            defer { item = current.pointee.ifa_next }
            let row = current.pointee
            let name = String(cString: row.ifa_name)
            guard physical.contains(name), !seen.contains(name), let address = row.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET),
                  row.ifa_flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &buffer,
                              socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            seen.insert(name)
            rows.append(UDPAdapterAddress(name: name, address: String(cString: buffer)))
        }
        return rows
    }
}
