//! Pure Rust Implementation
//!
//!

use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hmac::{Hmac, Mac, NewMac};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{BigUint, Hash, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512}; // Or `Aes128Gcm`
use std::sync::Arc;

use crate::digest::DigestAlgorithm;
use crate::errors::Error;
use crate::errors::ValidationError::InvalidSignature;
use crate::jwa::{
    AesGcmAlgorithm, EncryptionResult, SignatureAlgorithm, AES_GCM_NONCE_LENGTH, AES_GCM_TAG_SIZE,
};
use crate::jwk;
use crate::jws::{read_bytes, Secret};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

///!
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Unspecified;

impl Unspecified {
    fn description_() -> &'static str {
        "rust_impl::error::Unspecified"
    }
}

// This is required for the implementation of `std::error::Error`.
impl core::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(Self::description_())
    }
}

///!
pub type RsaKeyPair = RSAPrivateKey;

///!
pub struct EcdsaKeyPair;

pub(crate) fn rsa_keypair_from_file(path: &str) -> Result<Secret, Error> {
    let der = read_bytes(path)?;
    let key_pair = RSAPrivateKey::from_pkcs1(&der)?;
    Ok(Secret::RsaKeyPair(Arc::new(key_pair)))
}

pub(crate) fn ecdsa_keypair_from_file(
    _algorithm: SignatureAlgorithm,
    _path: &str,
) -> Result<Secret, Error> {
    unimplemented!()
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

    match algorithm {
        SignatureAlgorithm::HS256 => {
            let mut hmac = HmacSha256::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            let result = hmac.finalize();
            Ok(result.into_bytes().to_vec())
        }
        SignatureAlgorithm::HS384 => {
            let mut hmac = HmacSha384::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            let result = hmac.finalize();
            Ok(result.into_bytes().to_vec())
        }
        SignatureAlgorithm::HS512 => {
            let mut hmac = HmacSha512::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            let result = hmac.finalize();
            Ok(result.into_bytes().to_vec())
        }
        _ => unreachable!("Invalid signing algorithm."),
    }
}

fn compute_digest(
    algorithm: SignatureAlgorithm,
    data: &[u8],
) -> Result<(PaddingScheme, Vec<u8>), Error> {
    match algorithm {
        SignatureAlgorithm::RS256 => Ok((
            PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
            Sha256::digest(data).to_vec(),
        )),
        SignatureAlgorithm::RS384 => Ok((
            PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_384)),
            Sha384::digest(data).to_vec(),
        )),
        SignatureAlgorithm::RS512 => Ok((
            PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_512)),
            Sha512::digest(data).to_vec(),
        )),
        SignatureAlgorithm::PS256 => Ok((
            PaddingScheme::new_pss::<Sha256, _>(OsRng.clone()),
            Sha256::digest(data).to_vec(),
        )),
        SignatureAlgorithm::PS384 => Ok((
            PaddingScheme::new_pss::<Sha384, _>(OsRng.clone()),
            Sha384::digest(data).to_vec(),
        )),
        SignatureAlgorithm::PS512 => Ok((
            PaddingScheme::new_pss::<Sha512, _>(OsRng.clone()),
            Sha512::digest(data).to_vec(),
        )),
        _ => unreachable!("Invalid signing algorithm."),
    }
}

pub(crate) fn sign_rsa(
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    let mut rng = OsRng;
    let key_pair = match *secret {
        Secret::RsaKeyPair(ref key_pair) => key_pair,
        _ => Err("Invalid secret type. A RsaKeyPair is required".to_string())?,
    };
    let (padding_algorithm, digest) = compute_digest(algorithm, data)?;
    let signature = key_pair.sign_blinded(&mut rng, padding_algorithm, digest.as_slice())?;
    Ok(signature)
}

pub(crate) fn sign_ecdsa(
    _data: &[u8],
    _secret: &Secret,
    _algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, Error> {
    unimplemented!()
}

pub(crate) fn verify_hmac(
    expected_signature: &[u8],
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<(), Error> {
    let secret = match *secret {
        Secret::Bytes(ref secret) => secret,
        _ => Err("Invalid secret type. A byte array is required".to_string())?,
    };

    match algorithm {
        SignatureAlgorithm::HS256 => {
            let mut hmac = HmacSha256::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            hmac.verify(expected_signature)
                .map_err(|_| Error::ValidationError(InvalidSignature))?;
            Ok(())
        }
        SignatureAlgorithm::HS384 => {
            let mut hmac = HmacSha384::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            hmac.verify(expected_signature)
                .map_err(|_| Error::ValidationError(InvalidSignature))?;
            Ok(())
        }
        SignatureAlgorithm::HS512 => {
            let mut hmac = HmacSha512::new_varkey(secret.as_slice())
                .map_err(|_| Error::GenericError(String::from("Invalid Key Length")))?;
            hmac.update(data);
            hmac.verify(expected_signature)
                .map_err(|_| Error::ValidationError(InvalidSignature))?;
            Ok(())
        }
        _ => unreachable!("Invalid signing algorithm."),
    }
}

pub(crate) fn verify_public_key(
    expected_signature: &[u8],
    data: &[u8],
    secret: &Secret,
    algorithm: SignatureAlgorithm,
) -> Result<(), Error> {
    let (padding_algorithm, digest) = compute_digest(algorithm, data)?;
    match *secret {
        Secret::PublicKey(ref public_key) => {
            let public_key = RSAPublicKey::from_pkcs1(public_key.as_slice())?;
            public_key
                .verify(padding_algorithm, digest.as_slice(), &expected_signature)
                .map_err(|_| Error::UnspecifiedCryptographicError)?;
            Ok(())
        }
        Secret::RsaKeyPair(ref keypair) => {
            let public_key: RSAPublicKey = keypair.to_public_key();
            public_key
                .verify(padding_algorithm, digest.as_slice(), &expected_signature)
                .map_err(|_| Error::UnspecifiedCryptographicError)?;
            Ok(())
        }
        Secret::RSAModulusExponent { ref n, ref e } => {
            let public_key = RSAPublicKey::new(
                BigUint::new(n.to_u32_digits()),
                BigUint::new(e.to_u32_digits()),
            )?;
            public_key
                .verify(padding_algorithm, digest.as_slice(), &expected_signature)
                .map_err(|_| Error::UnspecifiedCryptographicError)?;
            Ok(())
        }
        /*Secret::EcdsaKeyPair(ref keypair) => {
            let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm
            {
                SignatureAlgorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
                SignatureAlgorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
                SignatureAlgorithm::ES512 => Err(Error::UnsupportedOperation)?,
                _ => unreachable!("Should not happen"),
            };

            let public_key =
                signature::UnparsedPublicKey::new(verification_algorithm, keypair.public_key());
            public_key.verify(&data, &expected_signature)?;
            Ok(())
        }*/
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
    let nonce = GenericArray::from_slice(nonce);
    let payload = Payload { msg: payload, aad };

    let ciphertext = match algorithm {
        AesGcmAlgorithm::A128GCM => {
            let key = GenericArray::from_slice(key.algorithm.octet_key()?);
            let cipher = Aes128Gcm::new(key);
            cipher.encrypt(nonce, payload).unwrap()
        }
        AesGcmAlgorithm::A256GCM => {
            let key = GenericArray::from_slice(key.algorithm.octet_key()?);
            let cipher = Aes256Gcm::new(key);
            cipher.encrypt(nonce, payload).unwrap()
        }
        _ => Err(Error::UnsupportedOperation)?,
    };

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);
    Ok(EncryptionResult {
        nonce: nonce.to_vec(),
        encrypted: ct.to_vec(),
        tag: tag.to_vec(),
        additional_data: aad.to_vec(),
    })
}

/// Decrypts a payload with AES GCM
pub(crate) fn aes_gcm_decrypt<T: Serialize + DeserializeOwned>(
    algorithm: &AesGcmAlgorithm,
    encrypted: &EncryptionResult,
    key: &jwk::JWK<T>,
) -> Result<Vec<u8>, Error> {
    let nonce = GenericArray::from_slice(encrypted.nonce.as_slice());
    let mut ciphertext = encrypted.encrypted.clone();
    ciphertext.extend_from_slice(encrypted.tag.as_slice());

    let payload = Payload {
        msg: &ciphertext,
        aad: encrypted.additional_data.as_slice(),
    };

    let plaintext = match algorithm {
        AesGcmAlgorithm::A128GCM => {
            let key = GenericArray::from_slice(key.algorithm.octet_key()?);
            let cipher = Aes128Gcm::new(key);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| Error::UnspecifiedCryptographicError)?
        }
        AesGcmAlgorithm::A256GCM => {
            let key = GenericArray::from_slice(key.algorithm.octet_key()?);
            let cipher = Aes256Gcm::new(key);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| Error::UnspecifiedCryptographicError)?
        }
        _ => Err(Error::UnsupportedOperation)?,
    };

    Ok(plaintext.to_vec())
}

/// Return a pseudo random number generator
/*pub(crate) fn rng() -> &'sOsRng {
    &OsRng
}*/

pub(crate) fn random_aes_gcm_nonce() -> Result<Vec<u8>, Error> {
    fill(AES_GCM_NONCE_LENGTH)
}

fn fill(length: usize) -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; length];
    rng_fill(&mut nonce)?;
    Ok(nonce)
}

pub(crate) fn rng_fill(dest: &mut [u8]) -> Result<(), Unspecified> {
    Ok(OsRng.fill_bytes(dest))
}

///!
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), Unspecified> {
    if a.eq(b) {
        Ok(())
    } else {
        Err(Unspecified)
    }
}

pub(crate) fn digest(algorithm: &DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        //DigestAlgorithm::SHA1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        DigestAlgorithm::SHA256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::SHA384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::SHA512 => Sha512::digest(data).to_vec(),
        //DigestAlgorithm::SHA512_256 => &ring::digest::SHA512_256,
        _ => unreachable!("Invalid digest algorithm."),
    }
}
