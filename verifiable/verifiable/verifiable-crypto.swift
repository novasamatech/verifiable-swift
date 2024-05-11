import verifiable_crypto

func internalDeriveMemberKey<GenericIntoRustString: IntoRustString>(_ entropy: GenericIntoRustString) -> RustString {
    RustString(ptr: __swift_bridge__$derive_member_key({ let rustString = entropy.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
}
func internalCreateProof<GenericIntoRustString: IntoRustString>(_ entropy: GenericIntoRustString, _ members: RustVec<GenericIntoRustString>, _ context: GenericIntoRustString, _ message: GenericIntoRustString) -> RustString {
    RustString(ptr: __swift_bridge__$create_proof({ let rustString = entropy.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), { let val = members; val.isOwned = false; return val.ptr }(), { let rustString = context.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), { let rustString = message.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
}


