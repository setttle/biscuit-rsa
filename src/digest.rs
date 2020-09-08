//! Secure cryptographic digests
//!
//! Currently used by JWK thumbprints.

/// A digest algorithm
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum DigestAlgorithm {
    ///
    SHA1,
    ///
    SHA256,
    ///
    SHA384,
    ///
    SHA512,
    ///
    SHA512_256,
}