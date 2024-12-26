## About

Swift bindings for [Bandersnatch](https://github.com/paritytech/verifiable) zero knowledge proof scheme. Using BandersnatchApi interface one can:

- derive ring member key for a given secret key (called entropy);
- create a proof for a given message, list of the ring members (keys) and context;
- sign a message

## Installation

### Swift Package Manager

Once you have Swift Package Manager setup add package to the dependencies in the ```Package.swift```:

```
dependencies: [
    .package(url: "https://github.com/novasamatech/verifiable-swift.git", from: "0.2.0")
]
```

### Cocoapods

First, add pod to the ```Podfile```:

```
pod BandersnatchApi, :git => 'https://github.com/novasamatech/verifiable-swift.git', :tag => '0.2.0'
```

Then run:

```
pod install
```

## Bindings creation

In case Rust library is updated one needs to rebuild the binding using the following steps:

1. Update ```Cargo.toml``` in the ```bindings``` directory to point to the right version of the rust library
2. Run ```build.sh``` from the bindings directory
3. In result, new version of the ```verifyable_crypto.xcframework``` will be built
