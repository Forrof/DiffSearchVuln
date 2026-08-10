// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "DiffSearchVulnCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DiffSearchVulnCore", targets: ["DiffSearchVulnCore"])
    ],
    targets: [
        .target(name: "DiffSearchVulnCore"),
        .testTarget(
            name: "DiffSearchVulnCoreTests",
            dependencies: ["DiffSearchVulnCore"]
        )
    ]
)
