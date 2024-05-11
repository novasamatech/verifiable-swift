// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "verifiable",
    products: [
        .library(
            name: "verifiable",
            targets: ["verifiable"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "verifiable-crypto",
            path: "./bindings/xcframework/verifiable_crypto.xcframework"
        ),
        .target(
            name: "verifiable",
            dependencies: ["verifiable-crypto"],
            path: "./verifiable/verifiable"
        ),
    ]
)
