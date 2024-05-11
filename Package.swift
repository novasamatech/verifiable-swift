// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "BandersnatchApi",
    products: [
        .library(
            name: "BandersnatchApi",
            targets: ["BandersnatchApi"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "verifiable-crypto",
            path: "./bindings/xcframework/verifiable_crypto.xcframework"
        ),
        .target(
            name: "BandersnatchApi",
            dependencies: ["verifiable-crypto"],
            path: "Sources"
        ),
    ]
)
