import verifiable_crypto

func internalDeriveMemberKey<GenericIntoRustString: IntoRustString>(_ entropy: GenericIntoRustString) -> RustString {
    RustString(ptr: __swift_bridge__$derive_member_key(prepareRustString(entropy)))
}

func internalCreateProof<GenericIntoRustString: IntoRustString>(_ entropy: GenericIntoRustString, _ members: RustVec<GenericIntoRustString>, _ context: GenericIntoRustString, _ message: GenericIntoRustString) -> RustString {
    RustString(ptr: __swift_bridge__$create_proof(
        prepareRustString(entropy),
        { let val = members; val.isOwned = false; return val.ptr }(),
        prepareRustString(context),
        prepareRustString(message)
    ))
}

func internalSign<GenericIntoRustString: IntoRustString>(_ entropy: GenericIntoRustString, _ message: GenericIntoRustString) -> RustString {
    RustString(
        ptr: __swift_bridge__$sign(
            prepareRustString(entropy),
            prepareRustString(message)
        )
    )
}

private func prepareRustString<GenericIntoRustString: IntoRustString>(_ value: GenericIntoRustString) -> UnsafeMutablePointer<CChar> {
    let rustString = value.intoRustString()
    rustString.isOwned = false
    return rustString.ptr.assumingMemoryBound(to: CChar.self)
}
