// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VERZLink",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "VERZLink", targets: ["VERZLink"])],
    targets: [.executableTarget(name: "VERZLink", path: "Sources/VERZLink"),
              .testTarget(name: "VERZLinkTests", dependencies: ["VERZLink"], path: "Tests/VERZLinkTests")]
)
