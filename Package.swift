// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EndpointHeartbeat",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
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
            name: "EndpointHeartbeatIOSIntegrationTests",
            dependencies: ["EndpointHeartbeatCore"],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "EndpointHeartbeatCLITests",
            dependencies: [
                "EndpointHeartbeatCore",
                .target(name: "EndpointHeartbeatCLI", condition: .when(platforms: [.macOS]))
            ]
        )
    ]
)
