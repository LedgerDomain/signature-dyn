use std::borrow::Cow;

use crate::{KeyType, Result, SignatureDynT, VerifierDynT};

/// Structure that represents a verifier without requiring direct use of the underlying cryptographic libraries.
/// Useful for interoperability.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct VerifierBytes<'a> {
    pub(crate) key_type: KeyType,
    pub(crate) byte_v: Cow<'a, [u8]>,
}

impl<'a> VerifierBytes<'a> {
    pub fn new(key_type: KeyType, byte_v: Cow<'a, [u8]>) -> Result<Self> {
        match key_type {
            KeyType::Ed25519 => {
                // TODO: Validation
            }
            KeyType::Ed448 => {
                // TODO: Validation
            }
            KeyType::P256 => {
                // TODO: Validation
            }
            KeyType::P384 => {
                // TODO: Validation
            }
            KeyType::P521 => {
                // TODO: Validation
            }
            KeyType::RSA => {
                // TODO: Validation
            }
            KeyType::Secp256k1 => {
                // TODO: Validation
            }
            KeyType::Sr25519 => {
                // TODO: Validation
            }
            KeyType::X25519 => {
                // TODO: Validation
            }
        }
        Ok(Self { key_type, byte_v })
    }
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    pub fn bytes(&self) -> &[u8] {
        self.byte_v.as_ref()
    }
    pub fn into_owned<'b: 'a>(self) -> VerifierBytes<'b> {
        VerifierBytes {
            key_type: self.key_type,
            byte_v: Cow::Owned(self.byte_v.into_owned()),
        }
    }
    pub fn to_owned<'b>(&self) -> VerifierBytes<'b> {
        VerifierBytes {
            key_type: self.key_type,
            byte_v: Cow::Owned(self.byte_v.to_vec()),
        }
    }
}

impl<'a> VerifierDynT for VerifierBytes<'a> {
    fn key_type(&self) -> KeyType {
        self.key_type
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.byte_v.clone()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureDynT) -> Result<()> {
        match self.key_type {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let ed25519_dalek_verifying_key = ed25519_dalek::VerifyingKey::try_from(self)?;
                    let ed25519_dalek_signature =
                        ed25519_dalek::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature::Verifier;
                    ed25519_dalek_verifying_key
                        .verify(message_byte_v, &ed25519_dalek_signature)
                        .map_err(|e| {
                            crate::error!("Ed25519_SHA_512 signature verification failed: {}", e)
                        })
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let ed448_goldilocks_verifying_key =
                        ed448_goldilocks::VerifyingKey::try_from(self)?;
                    let ed448_goldilocks_signature =
                        ed448_goldilocks::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature_3::Verifier;
                    ed448_goldilocks_verifying_key
                        .verify(message_byte_v, &ed448_goldilocks_signature)
                        .map_err(|e| crate::error!("Ed448 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("ed448-goldilocks feature not enabled");
                }
            }
            KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    let p256_verifying_key = p256::ecdsa::VerifyingKey::try_from(self)?;
                    let p256_signature =
                        p256::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature::Verifier;
                    p256_verifying_key
                        .verify(message_byte_v, &p256_signature)
                        .map_err(|e| crate::error!("P256 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "p256"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("p256 feature not enabled");
                }
            }
            KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    let p384_verifying_key = p384::ecdsa::VerifyingKey::try_from(self)?;
                    let p384_signature =
                        p384::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature::Verifier;
                    p384_verifying_key
                        .verify(message_byte_v, &p384_signature)
                        .map_err(|e| crate::error!("P384 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "p384"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("p384 feature not enabled");
                }
            }
            KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    let p521_verifying_key = p521::ecdsa::VerifyingKey::try_from(self)?;
                    let p521_signature =
                        p521::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature_3::Verifier;
                    p521_verifying_key
                        .verify(message_byte_v, &p521_signature)
                        .map_err(|e| crate::error!("P521 signature verification failed: {}", e))
                }
                #[cfg(not(feature = "p521"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("p521 feature not enabled");
                }
            }
            KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    let k256_verifying_key = k256::ecdsa::VerifyingKey::try_from(self)?;
                    let k256_signature =
                        k256::ecdsa::Signature::try_from(&signature.to_signature_bytes())?;
                    use signature::Verifier;
                    k256_verifying_key
                        .verify(message_byte_v, &k256_signature)
                        .map_err(|e| {
                            crate::error!("Secp256k1 signature verification failed: {}", e)
                        })
                }
                #[cfg(not(feature = "k256"))]
                {
                    let _ = message_byte_v;
                    let _ = signature;
                    panic!("k256 feature not enabled");
                }
            }
            _ => {
                todo!();
            }
        }
    }
}
