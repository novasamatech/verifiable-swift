extern crate core;
extern crate verifiable;

use verifiable::GenerateVerifiable;
use verifiable::ring::bandersnatch::BandersnatchVrfVerifiable;
use verifiable::ring::RingDomainSize;
use base64::{engine::general_purpose::STANDARD, Engine};

#[swift_bridge::bridge]
mod ffi {    
    extern "Rust" {
        #[swift_bridge(swift_name = "deriveMemberKey")]
        fn derive_member_key(entropy: String) -> String;

        #[swift_bridge(swift_name = "create_proof")]
        fn create_proof(entropy: String, members: Vec<String>, context: String, message: String, domain_size: u32) -> String;

        #[swift_bridge(swift_name = "sign")]
        fn sign(entropy: String, message: String) -> String;

        #[swift_bridge(swift_name = "derive_alias")]
        fn derive_alias(entropy: String, context: String) -> String;

        #[swift_bridge(swift_name = "get_entropy_length")]
        fn get_entropy_length() -> usize;

        #[swift_bridge(swift_name = "get_entropy_length")]
        fn get_member_key_length() -> usize;
    }
}

const ENTROPY_LENGTH: usize = 32;
const MEMBER_KEY_LENGTH: usize = 32;

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
    let public = BandersnatchVrfVerifiable::member_from_secret(&secret);

    STANDARD.encode(public.as_ref())
}

#[no_mangle]
fn create_proof(entropy: String, members: Vec<String>, context: String, message: String, domain_size: u32) -> String {
    let ring_domain = match decode_domain_size(domain_size) {
        Ok(domain) => domain,
        Err(err) => return err,
    };

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

    let commitment = match BandersnatchVrfVerifiable::open(
        ring_domain.into(),
        &public,
        members.into_iter(),
    ) {
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

#[no_mangle]
fn get_entropy_length() -> usize {
    ENTROPY_LENGTH
}

#[no_mangle]
fn get_member_key_length() -> usize {
    MEMBER_KEY_LENGTH
}

fn decode_domain_size(domain_size: u32) -> Result<RingDomainSize, String> {
    match domain_size {
        11 => Ok(RingDomainSize::Domain11),
        12 => Ok(RingDomainSize::Domain12),
        16 => Ok(RingDomainSize::Domain16),
        _ => Err(error()),
    }
}

fn decode_members(members: Vec<String>) -> Result<Vec<[u8; MEMBER_KEY_LENGTH]>, String> {
    members.into_iter().map(|base64_string| {
        let bytes = decode_slice(&base64_string)?;

        if bytes.len() != MEMBER_KEY_LENGTH {
            return Err(error());
        }

        let slice: [u8; MEMBER_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| error())?;

        Ok(slice)
    }).collect()
}

fn decode_slice(base64_string: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(base64_string).map_err(|_| error())
}

fn decode_entropy(entropy: &str) -> Result<[u8; ENTROPY_LENGTH], String> {
    let entropy_bytes = STANDARD.decode(entropy).map_err(|_| error())?;

    if entropy_bytes.len() != ENTROPY_LENGTH {
        return Err(error());
    }

    let entropy_slice: [u8; ENTROPY_LENGTH] = entropy_bytes
        .try_into()
        .map_err(|_| error())?;

    Ok(entropy_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entropy() -> String {
        STANDARD.encode([0u8; 32])
    }

    #[test]
    fn test_derive_member_key() {
        let result = derive_member_key(test_entropy());
        assert_ne!(result, "-1");

        let decoded = STANDARD.decode(&result).unwrap();
        assert_eq!(decoded.len(), MEMBER_KEY_LENGTH);
    }

    #[test]
    fn test_derive_member_key_deterministic() {
        let a = derive_member_key(test_entropy());
        let b = derive_member_key(test_entropy());
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_member_key_bad_entropy() {
        let short = STANDARD.encode([0u8; 16]);
        assert_eq!(derive_member_key(short), "-1");

        assert_eq!(derive_member_key("not-base64!!!".to_string()), "-1");
    }

    #[test]
    fn test_sign() {
        let message = STANDARD.encode(b"hello");
        let result = sign(test_entropy(), message);
        assert_ne!(result, "-1");

        let decoded = STANDARD.decode(&result).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_derive_alias() {
        let context = STANDARD.encode(b"pop:polkadot.network/priv-vouchr");
        let result = derive_alias(test_entropy(), context.clone());
        assert_ne!(result, "-1");

        // deterministic
        let result2 = derive_alias(test_entropy(), context);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_create_proof_domain11() {
        let members: Vec<String> = (0u8..10).map(|i| {
            let entropy = STANDARD.encode([i; 32]);
            derive_member_key(entropy)
        }).collect();

        let context = STANDARD.encode(b"pop:polkadot.network/mob-rule   ");
        let message = STANDARD.encode(b"hello");

        let result = create_proof(test_entropy(), members, context, message, 11);
        assert_ne!(result, "-1");

        let decoded = STANDARD.decode(&result).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_create_proof_domain12() {
        let members: Vec<String> = (0u8..10).map(|i| {
            let entropy = STANDARD.encode([i; 32]);
            derive_member_key(entropy)
        }).collect();

        let context = STANDARD.encode(b"pop:polkadot.network/mob-rule   ");
        let message = STANDARD.encode(b"hello");

        let result = create_proof(test_entropy(), members, context, message, 12);
        assert_ne!(result, "-1");

        let decoded = STANDARD.decode(&result).unwrap();
        assert!(!decoded.is_empty());
    }

    #[test]
    fn test_create_proof_invalid_domain() {
        let members: Vec<String> = (0u8..3).map(|i| {
            let entropy = STANDARD.encode([i; 32]);
            derive_member_key(entropy)
        }).collect();

        let context = STANDARD.encode(b"context");
        let message = STANDARD.encode(b"hello");

        let result = create_proof(test_entropy(), members, context, message, 99);
        assert_eq!(result, "-1");
    }

    #[test]
    fn test_get_lengths() {
        assert_eq!(get_entropy_length(), 32);
        assert_eq!(get_member_key_length(), 32);
    }
}