#[cfg(feature = "async")]
mod async_extractable_signer_t;
#[cfg(feature = "async")]
mod async_signer_t;
#[cfg(feature = "ed25519-dalek")]
mod ed25519_dalek;
#[cfg(feature = "ed448-goldilocks")]
mod ed448_goldilocks;
mod error;
mod extractable_signer_t;
mod generate_random;
#[cfg(feature = "k256")]
mod k256;
mod key_type;
#[cfg(feature = "p256")]
mod p256;
#[cfg(feature = "p384")]
mod p384;
#[cfg(feature = "p521")]
mod p521;
#[cfg(feature = "pkcs8")]
mod pkcs8;
mod signature_bytes;
mod signature_t;
mod signer_bytes;
mod signer_t;
mod verifier_bytes;
mod verifier_t;

pub use {
    error::Error,
    extractable_signer_t::ExtractableSignerT,
    generate_random::GenerateRandom,
    key_type::{KEY_TYPE_V, KeyType},
    signature_bytes::SignatureBytes,
    signature_t::SignatureT,
    signer_bytes::SignerBytes,
    signer_t::SignerT,
    verifier_bytes::VerifierBytes,
    verifier_t::VerifierT,
};
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(feature = "pkcs8")]
pub use pkcs8::{PKCS8Read, PKCS8Write};
#[cfg(feature = "async")]
pub use {async_extractable_signer_t::AsyncExtractableSignerT, async_signer_t::AsyncSignerT};

/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const ED25519_JOSE_ALGORITHM: &str = "Ed25519";
/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const ED448_JOSE_ALGORITHM: &str = "Ed448";
/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const P256_JOSE_ALGORITHM: &str = "ES256";
/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const P384_JOSE_ALGORITHM: &str = "ES384";
/// See <https://www.iana.org/assignments/jose/jose.xhtml>.  Note that the "512" in "ES512" is not a typo,
/// as it refers to the bit size of the hash function used.
pub const P521_JOSE_ALGORITHM: &str = "ES512";
/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const SECP256K1_JOSE_ALGORITHM: &str = "ES256K";
