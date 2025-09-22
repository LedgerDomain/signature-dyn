use std::borrow::Cow;

use crate::{KeyType, Result, SignatureDynT, SignerDynT, VerifierDynT};

/// This is a generic data structure to represent private keys that doesn't require direct use of the underlying
/// cryptographic libraries.  This is useful for serialization and deserialization of private keys.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SignerBytes<'a> {
    pub(crate) key_type: KeyType,
    pub(crate) byte_v: Cow<'a, [u8]>,
}

impl<'a> SignerBytes<'a> {
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
    pub fn into_byte_v(self) -> Cow<'a, [u8]> {
        self.byte_v
    }
    pub fn into_owned<'b>(self) -> SignerBytes<'b> {
        SignerBytes {
            key_type: self.key_type,
            byte_v: Cow::Owned(self.byte_v.into_owned()),
        }
    }
    pub fn to_owned<'b>(&self) -> SignerBytes<'b> {
        SignerBytes {
            key_type: self.key_type.clone(),
            byte_v: Cow::Owned(self.byte_v.to_vec()),
        }
    }
}

#[cfg(feature = "pkcs8")]
impl<'a> crate::PKCS8Write for SignerBytes<'a> {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        match self.key_type {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let signing_key = ed25519_dalek::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let signing_key = ed448_goldilocks::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    let signing_key = p256::ecdsa::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    let signing_key = p384::ecdsa::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    let signing_key = p521::ecdsa::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    let signing_key = k256::ecdsa::SigningKey::try_from(self)?;
                    signing_key.write_to_pkcs8_pem_file(path)?;
                }
            }
            _ => {
                unimplemented!("Key type {:?} not supported yet", self.key_type);
            }
        }
        Ok(())
    }
}

impl<'a> SignerDynT for SignerBytes<'a> {
    fn key_type(&self) -> KeyType {
        self.key_type
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.byte_v.clone()
    }
    fn verifier_dyn(&self) -> Result<Box<dyn VerifierDynT>> {
        match self.key_type {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let signing_key = ed25519_dalek::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let signing_key = ed448_goldilocks::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    panic!("ed448-goldilocks feature not enabled");
                }
            }
            KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    let signing_key = p256::ecdsa::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key().clone();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "p256"))]
                {
                    panic!("p256 feature not enabled");
                }
            }
            KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    let signing_key = p384::ecdsa::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key().clone();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "p384"))]
                {
                    panic!("p384 feature not enabled");
                }
            }
            KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    let signing_key = p521::ecdsa::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key().clone();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "p521"))]
                {
                    panic!("p521 feature not enabled");
                }
            }
            KeyType::RSA => {
                unimplemented!("RSA is not supported currently");
            }
            KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    let signing_key = k256::ecdsa::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key().clone();
                    let verifier_dyn_b: Box<dyn VerifierDynT> = Box::new(verifying_key);
                    Ok(verifier_dyn_b)
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("k256 feature not enabled");
                }
            }
            KeyType::Sr25519 => {
                unimplemented!("Sr25519 is not supported currently");
            }
            KeyType::X25519 => {
                unimplemented!("X25519 is not supported currently");
            }
        }
    }
    fn to_signer_bytes<'b, 's: 'b>(&'s self) -> SignerBytes<'b> {
        self.clone()
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureDynT>> {
        match self.key_type {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let signing_key = ed25519_dalek::SigningKey::try_from(self)?;
                    use signature::Signer;
                    let signature = signing_key.try_sign(message_byte_v).map_err(|e| {
                        crate::error!("Ed25519_SHA_512 signature signing failed: {}", e)
                    })?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    let _ = message_byte_v;
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let signing_key = ed448_goldilocks::SigningKey::try_from(self)?;
                    use signature_3::Signer;
                    let signature: ed448_goldilocks::Signature = signing_key
                        .try_sign(message_byte_v)
                        .map_err(|e| crate::error!("Ed448 signature signing failed: {}", e))?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    let _ = message_byte_v;
                    panic!("ed448-goldilocks feature not enabled");
                }
            }
            KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    let signing_key = p256::ecdsa::SigningKey::try_from(self)?;
                    use signature::Signer;
                    let signature: p256::ecdsa::Signature = signing_key
                        .try_sign(message_byte_v)
                        .map_err(|e| crate::error!("P256 signature signing failed: {}", e))?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "p256"))]
                {
                    let _ = message_byte_v;
                    panic!("p256 feature not enabled");
                }
            }
            KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    let signing_key = p384::ecdsa::SigningKey::try_from(self)?;
                    use signature::Signer;
                    let signature: p384::ecdsa::Signature = signing_key
                        .try_sign(message_byte_v)
                        .map_err(|e| crate::error!("P384 signature signing failed: {}", e))?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "p384"))]
                {
                    let _ = message_byte_v;
                    panic!("p384 feature not enabled");
                }
            }
            KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    let signing_key = p521::ecdsa::SigningKey::try_from(self)?;
                    use signature_3::Signer;
                    let signature: p521::ecdsa::Signature = signing_key
                        .try_sign(message_byte_v)
                        .map_err(|e| crate::error!("P521 signature signing failed: {}", e))?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "p521"))]
                {
                    let _ = message_byte_v;
                    panic!("p521 feature not enabled");
                }
            }
            // KeyType::RSA => {
            //     unimplemented!("RSA is not supported currently");
            // }
            KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    let signing_key = k256::ecdsa::SigningKey::try_from(self)?;
                    use signature::Signer;
                    let signature: k256::ecdsa::Signature = signing_key
                        .try_sign(message_byte_v)
                        .map_err(|e| crate::error!("Secp256k1 signature signing failed: {}", e))?;
                    Ok(Box::new(signature))
                }
                #[cfg(not(feature = "k256"))]
                {
                    let _ = message_byte_v;
                    panic!("k256 feature not enabled");
                }
            }
            // KeyType::Sr25519 => {
            //     unimplemented!("Sr25519 is not supported currently");
            // }
            // KeyType::X25519 => {
            //     unimplemented!("X25519 is not supported currently");
            // }
            _ => {
                todo!();
            }
        }
    }
}
