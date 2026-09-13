import Foundation

func fail(_ message: String) -> Never {
    fputs("UDP signing verification failed: \(message)\n", stderr)
    exit(1)
}
func plist(_ data: Data) -> [String: Any] {
    guard let value = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
        fail("not a property list")
    }
    return value
}
func entitlements(_ url: URL) -> [String: Any] {
    let task = Process(); let output = Pipe()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    task.arguments = ["-d", "--entitlements", ":-", url.path]
    task.standardOutput = output; task.standardError = FileHandle.nullDevice
    do { try task.run() } catch { fail(error.localizedDescription) }
    let data = output.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
    guard task.terminationStatus == 0 else { fail("cannot read signed entitlements") }
    return plist(data)
}
let sourceCheck = CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--source"
guard CommandLine.arguments.count == 2 || sourceCheck else { fail("usage: verify-udp-signing.swift [--source] App.app-or-project") }
let app = URL(fileURLWithPath: CommandLine.arguments.last!)
let ext = app.appendingPathComponent("Contents/Library/SystemExtensions/com.omaralabed.verzlink.classic.udp.systemextension")
func sourcePlist(_ name: String) -> [String: Any] {
    guard let data = try? Data(contentsOf: app.appendingPathComponent("Resources/" + name)) else { fail("cannot read \(name)") }
    return plist(data)
}
let host = sourceCheck ? sourcePlist("UDP-App.entitlements") : entitlements(app)
let provider = sourceCheck ? sourcePlist("UDP-Proxy.entitlements") : entitlements(ext)
let infoURL = sourceCheck ? app.appendingPathComponent("Resources/UDP-Proxy-Info.plist") : ext.appendingPathComponent("Contents/Info.plist")
guard let data = try? Data(contentsOf: infoURL),
      let network = plist(data)["NetworkExtension"] as? [String: Any],
      let service = network["NEMachServiceName"] as? String,
      let hostGroups = host["com.apple.security.application-groups"] as? [String],
      let groups = provider["com.apple.security.application-groups"] as? [String],
      groups.contains(where: { hostGroups.contains($0) && service.hasPrefix($0 + ".") }) else {
    fail("NEMachServiceName must be prefixed by an App Group signed into both app and provider")
}
if !sourceCheck {
    guard host["com.apple.developer.team-identifier"] as? String == "H7728UD4B3",
          provider["com.apple.developer.team-identifier"] as? String == "H7728UD4B3" else { fail("wrong signing team") }
}
for value in [host, provider] {
    guard (value["com.apple.developer.networking.networkextension"] as? [String])?.contains("app-proxy-provider") == true else {
        fail("missing app-proxy entitlement")
    }
}
print(sourceCheck ? "Verified source UDP service/App Group entitlement mapping." : "Verified signed UDP service/App Group mapping and Omar Alabed team.")
