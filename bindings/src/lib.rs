extern crate core;
extern crate verifiable;

use verifiable::GenerateVerifiable;
use verifiable::ring_vrf_impl::{BandersnatchVrfVerifiable, EncodedPublicKey};
use base64::{engine::general_purpose::STANDARD, Engine};

#[swift_bridge::bridge]
mod ffi {    
    extern "Rust" {
        #[swift_bridge(swift_name = "deriveMemberKey")]
        fn derive_member_key(entropy: String) -> String;

        #[swift_bridge(swift_name = "create_proof")]
        fn create_proof(entropy: String, members: Vec<String>, context: String, message: String) -> String;

        #[swift_bridge(swift_name = "sign")]
        fn sign(entropy: String, message: String) -> String;

        #[swift_bridge(swift_name = "derive_alias")]
        fn derive_alias(entropy: String, context: String) -> String;
    }
}

fn error() -> String {
    "-1".to_string()
}

#[no_mangle]
fn derive_member_key(entropy: String) -> String {
    let entropy_slice = match decode_entropy(&entropy) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let secret = BandersnatchVrfVerifiable::new_secret(entropy_slice);
    let public = BandersnatchVrfVerifiable::member_from_secret(&secret).0;

    STANDARD.encode(public.as_ref())
}

#[no_mangle]
fn create_proof(entropy: String, members: Vec<String>, context: String, message: String) -> String {
    let entropy_slice = match decode_entropy(&entropy) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let secret = BandersnatchVrfVerifiable::new_secret(entropy_slice);
    let public = BandersnatchVrfVerifiable::member_from_secret(&secret);

    let context_slice = match decode_slice(&context) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let message_slice = match decode_slice(&message) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let members = match decode_members(members) {
        Ok(decoded_members) => decoded_members,
        Err(err) => return err,
    };

    let commitment = match BandersnatchVrfVerifiable::open(&public, members.into_iter()) {
        Ok(commitment_value) => commitment_value,
        Err(_) => return error(),
    };

    let (proof, _) = match BandersnatchVrfVerifiable::create(
        commitment,
        &secret,
        &context_slice,
        &message_slice,
    ) {
        Ok(tuple) => tuple,
        Err(_) => return error(),
    };

    STANDARD.encode(proof)
}

#[no_mangle]
fn sign(entropy: String, message: String) -> String {
    let entropy_slice = match decode_entropy(&entropy) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let secret = BandersnatchVrfVerifiable::new_secret(entropy_slice);

    let message_slice = match decode_slice(&message) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let signature = match BandersnatchVrfVerifiable::sign(&secret, &message_slice) {
        Ok(sig) => sig,
        Err(_) => return error(),
    };

    STANDARD.encode(signature)
}

#[no_mangle]
fn derive_alias(entropy: String, context: String) -> String {
    let entropy_slice = match decode_entropy(&entropy) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let secret = BandersnatchVrfVerifiable::new_secret(entropy_slice);

    let context_slice = match decode_slice(&context) {
        Ok(slice) => slice,
        Err(err) => return err,
    };

    let alias = match BandersnatchVrfVerifiable::alias_in_context(
        &secret,
        &context_slice
    ) {
        Ok(alias_value) => alias_value,
        Err(_) => return error(),
    };

    STANDARD.encode(alias)
}

fn decode_members(members: Vec<String>) -> Result<Vec<EncodedPublicKey>, String> {
    members.into_iter().map(|base64_string| {
        let bytes = decode_slice(&base64_string)?;
        
        if bytes.len() != 32 {
            return Err(error());
        }

        let slice: [u8; 32] = bytes
            .try_into()
            .map_err(|_| error())?;
        
        Ok(EncodedPublicKey(slice))
    }).collect()
}

fn decode_slice(base64_string: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(base64_string).map_err(|_| error())
}

fn decode_entropy(entropy: &str) -> Result<[u8; 32], String> {
    let entropy_bytes = STANDARD.decode(entropy).map_err(|_| error())?;

    if entropy_bytes.len() != 32 {
        return Err(error());
    }

    let entropy_slice: [u8; 32] = entropy_bytes
        .try_into()
        .map_err(|_| error())?;

    Ok(entropy_slice)
}