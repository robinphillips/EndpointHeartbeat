// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EndpointHeartbeat",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "EndpointHeartbeatCore", targets: ["EndpointHeartbeatCore"]),
        .executable(name: "endpoint-heartbeat", targets: ["EndpointHeartbeatCLI"])
    ],
    targets: [
        .target(name: "EndpointHeartbeatCore"),
        .executableTarget(
            name: "EndpointHeartbeatCLI",
            dependencies: ["EndpointHeartbeatCore"]
        ),
        .testTarget(
            name: "EndpointHeartbeatCoreTests",
            dependencies: ["EndpointHeartbeatCore"]
        ),
        .testTarget(
            name: "EndpointHeartbeatCLITests",
            dependencies: ["EndpointHeartbeatCLI", "EndpointHeartbeatCore"]
        )
    ]
)
