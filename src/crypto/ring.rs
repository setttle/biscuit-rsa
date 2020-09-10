//! Ring Based Implementation
//!
//!
//!

use once_cell::sync::Lazy;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use ring::{aead, hmac, rand, signature};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use ring::rand::SecureRandom;

use crate::digest::DigestAlgorithm;
use crate::errors::Error;
use crate::jwa::{
    AesGcmAlgorithm, EncryptionResult, SignatureAlgorithm, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_SIZE,
};
use crate::jwk;
use crate::jws::{read_bytes, Secret};
use ring::error::Unspecified;
use std::sync::Arc;

///!
pub type RsaKeyPair = ring::signature::RsaKeyPair;

///!
pub type EcdsaKeyPair = ring::signature::EcdsaKeyPair;

pub(crate) fn rsa_keypair_from_file(path: &str) -> Result<Secret, Error> {
    let der = read_bytes(path)?;
    let key_pair = RsaKeyPair::from_der(der.as_slice())?;
    Ok(Secret::RsaKeyPair(Arc::new(key_pair)))
}

pub(crate) fn ecdsa_keypair_from_file(
    algorithm: SignatureAlgorithm,
    path: &str,
) -> Result<Secret, Error> {
    let der = read_bytes(path)?;
    let ring_algorithm = match algorithm {
        SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => return Err(Error::UnsupportedOperation),
    };
    let key_pair = EcdsaKeyPair::from_pkcs8(ring_algorithm, der.as_slice())?;
    Ok(Secret::EcdsaKeyPair(Arc::new(key_pair)))
}

pub(crate) fn sign_hmac(
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    let secret = match *secret {
        Secret::Bytes(ref secret) => secret,
        _ => Err("Invalid secret type. A byte array is required".to_string())?,
    };

    let algorithm = match algorithm {
        SignatureAlgorithm::HS256 => &hmac::HMAC_SHA256,
        SignatureAlgorithm::HS384 => &hmac::HMAC_SHA384,
        SignatureAlgorithm::HS512 => &hmac::HMAC_SHA512,
        _ => unreachable!("Should not happen"),
    };
    let key = hmac::Key::new(*algorithm, secret);
    Ok(hmac::sign(&key, data).as_ref().to_vec())
}

pub(crate) fn sign_rsa(
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    let key_pair = match *secret {
        Secret::RsaKeyPair(ref key_pair) => key_pair,
        _ => Err("Invalid secret type. A RsaKeyPair is required".to_string())?,
    };

    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public_modulus_len()];
    let padding_algorithm: &dyn signature::RsaEncoding = match algorithm {
        SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_SHA256,
        SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_SHA384,
        SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_SHA512,
        SignatureAlgorithm::PS256 => &signature::RSA_PSS_SHA256,
        SignatureAlgorithm::PS384 => &signature::RSA_PSS_SHA384,
        SignatureAlgorithm::PS512 => &signature::RSA_PSS_SHA512,
        _ => unreachable!("Should not happen"),
    };

    key_pair.sign(padding_algorithm, &rng, data, &mut signature)?;
    Ok(signature)
}

pub(crate) fn sign_ecdsa(
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    let key_pair = match *secret {
        Secret::EcdsaKeyPair(ref key_pair) => key_pair,
        _ => Err("Invalid secret type. An EcdsaKeyPair is required".to_string())?,
    };
    if let SignatureAlgorithm::ES512 = algorithm {
        // See https://github.com/briansmith/ring/issues/268
        Err(Error::UnsupportedOperation)
    } else {
        let rng = rand::SystemRandom::new();
        let sig = key_pair.as_ref().sign(&rng, data)?;
        Ok(sig.as_ref().to_vec())
    }
}

pub(crate) fn verify_hmac(
    expected_signature: &[u8],
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<(), Error> {
    let actual_signature = sign_hmac(data, secret, algorithm)?;
    verify_slices_are_equal(expected_signature, actual_signature.as_ref())?;
    Ok(())
}

pub(crate) fn verify_public_key(
    expected_signature: &[u8],
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<(), Error> {
    match *secret {
        Secret::PublicKey(ref public_key) => {
            let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm {
                SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                _ => unreachable!("Should not happen"),
            };

            let public_key =
                signature::UnparsedPublicKey::new(verification_algorithm, public_key.as_slice());
            public_key.verify(&data, &expected_signature)?;
            Ok(())
        }
        Secret::RsaKeyPair(ref keypair) => {
            let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm {
                SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                _ => unreachable!("Should not happen"),
            };

            let public_key =
                signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
            public_key.verify(&data, &expected_signature)?;
            Ok(())
        }
        Secret::RSAModulusExponent { ref n, ref e } => {
            let params = match algorithm {
                SignatureAlgorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                SignatureAlgorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                SignatureAlgorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                SignatureAlgorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
                SignatureAlgorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
                SignatureAlgorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
                _ => unreachable!("(n,e) secret with a non-rsa algorithm should not happen"),
            };

            let n_big_endian = n.to_bytes_be();
            let e_big_endian = e.to_bytes_be();
            let public_key = signature::RsaPublicKeyComponents {
                n: n_big_endian,
                e: e_big_endian,
            };
            public_key.verify(params, &data, &expected_signature)?;
            Ok(())
        }
        Secret::EcdsaKeyPair(ref keypair) => {
            let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm {
                SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                _ => unreachable!("Should not happen"),
            };

            let public_key =
                signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
            public_key.verify(&data, &expected_signature)?;
            Ok(())
        }
        _ => unreachable!("This is a private method and should not be called erroneously."),
    }
}

/// Encrypt a payload with AES GCM
pub(crate) fn aes_gcm_encrypt<T: Serialize + DeserializeOwned>(
    algorithm: &AesGcmAlgorithm,
    payload: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key: &jwk::JWK<T>,
) -> Result<EncryptionResult, Error> {
    let ring_algo = match algorithm {
        AesGcmAlgorithm::A128GCM => &aead::AES_128_GCM,
        AesGcmAlgorithm::A256GCM => &aead::AES_256_GCM,
        _ => Err(Error::UnsupportedOperation)?,
    };

    // JWA needs a 128 bit tag length. We need to assert that the algorithm has 128 bit tag length
    assert_eq!(ring_algo.tag_len(), AES_GCM_TAG_SIZE);
    // Also the nonce (or initialization vector) needs to be 96 bits
    assert_eq!(ring_algo.nonce_len(), AES_GCM_NONCE_LENGTH);

    let key = key.algorithm.octet_key()?;
    let key = aead::UnboundKey::new(ring_algo, key)?;
    let sealing_key = aead::LessSafeKey::new(key);

    let mut in_out: Vec<u8> = payload.to_vec();
    let tag = sealing_key.seal_in_place_separate_tag(
        aead::Nonce::try_assume_unique_for_key(nonce)?,
        aead::Aad::from(aad),
        &mut in_out,
    )?;

    Ok(EncryptionResult {
        nonce: nonce.to_vec(),
        encrypted: in_out,
        tag: tag.as_ref().to_vec(),
        additional_data: aad.to_vec(),
    })
}

/// Decrypts a payload with AES GCM
pub(crate) fn aes_gcm_decrypt<T: Serialize + DeserializeOwned>(
    algorithm: &AesGcmAlgorithm,
    encrypted: &EncryptionResult,
    key: &jwk::JWK<T>,
) -> Result<Vec<u8>, Error> {
    let ring_algo = match algorithm {
        AesGcmAlgorithm::A128GCM => &aead::AES_128_GCM,
        AesGcmAlgorithm::A256GCM => &aead::AES_256_GCM,
        _ => Err(Error::UnsupportedOperation)?,
    };

    // JWA needs a 128 bit tag length. We need to assert that the algorithm has 128 bit tag length
    assert_eq!(ring_algo.tag_len(), AES_GCM_TAG_SIZE);
    // Also the nonce (or initialization vector) needs to be 96 bits
    assert_eq!(ring_algo.nonce_len(), AES_GCM_NONCE_LENGTH);

    let key = key.algorithm.octet_key()?;
    let key = aead::UnboundKey::new(ring_algo, key)?;
    let opening_key = aead::LessSafeKey::new(key);

    let mut in_out = encrypted.encrypted.to_vec();
    in_out.append(&mut encrypted.tag.to_vec());

    let plaintext = opening_key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(&encrypted.nonce)?,
        aead::Aad::from(&encrypted.additional_data),
        &mut in_out,
    )?;
    Ok(plaintext.to_vec())
}

/// Return a pseudo random number generator
pub(crate) fn rng() -> &'static SystemRandom {
    use std::ops::Deref;
    static RANDOM: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);
    RANDOM.deref()
}

pub(crate) fn random_aes_gcm_nonce() -> Result<Vec<u8>, Error> {
    fill(AES_GCM_NONCE_LENGTH)
}

fn fill(length: usize) -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; length];
    rng_fill(&mut nonce)?;
    Ok(nonce)
}

pub(crate) fn rng_fill(dest: &mut [u8]) -> Result<(), Unspecified> {
    rng().fill(dest)
}

pub(crate) fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), Unspecified> {
    ring::constant_time::verify_slices_are_equal(a, b)
}

pub(crate) fn digest(algorithm: &DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    let ring_algo = match algorithm {
        DigestAlgorithm::SHA1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        DigestAlgorithm::SHA256 => &ring::digest::SHA256,
        DigestAlgorithm::SHA384 => &ring::digest::SHA384,
        DigestAlgorithm::SHA512 => &ring::digest::SHA512,
        DigestAlgorithm::SHA512_256 => &ring::digest::SHA512_256,
    };
    ring::digest::digest(ring_algo, data)
        .as_ref()
        .to_vec()
        .clone()
}
