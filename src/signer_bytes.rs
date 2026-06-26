use zeroize::Zeroizing;

use crate::{
    KeyType, Result, SignatureT, SignerT, VerifierT, ensure,
    extractable_signer_t::ExtractableSignerT,
};

/// This is a generic data structure to represent private keys that doesn't require direct use of the underlying
/// cryptographic libraries.  This is useful for serialization and deserialization of private keys.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SignerBytes {
    pub(crate) key_type: KeyType,
    pub(crate) byte_v: Zeroizing<Vec<u8>>,
}

impl SignerBytes {
    pub fn new(key_type: KeyType, byte_v: Zeroizing<Vec<u8>>) -> Result<Self> {
        Self::validate_key_type(key_type, byte_v.as_slice())?;
        Ok(Self { key_type, byte_v })
    }
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    pub fn bytes(&self) -> &[u8] {
        self.byte_v.as_ref()
    }
    /// Forgets the KeyType and returns the private key material as a Zeroizing<Vec<u8>>.
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.byte_v)
    }
    fn validate_key_type(key_type: KeyType, byte_v: &[u8]) -> Result<()> {
        match key_type {
            KeyType::Ed25519 => {
                ensure!(byte_v.len() == 32, "expected 32 bytes for Ed25519");
            }
            KeyType::Ed448 => {
                ensure!(byte_v.len() == 57, "expected 57 bytes for Ed448");
            }
            KeyType::P256 => {
                ensure!(byte_v.len() == 32, "expected 32 bytes for P256");
            }
            KeyType::P384 => {
                ensure!(byte_v.len() == 48, "expected 48 bytes for P384");
            }
            KeyType::P521 => {
                ensure!(byte_v.len() == 66, "expected 66 bytes for P521");
            }
            KeyType::RSA => {
                // TODO: Validation
            }
            KeyType::Secp256k1 => {
                ensure!(byte_v.len() == 32, "expected 32 bytes for Secp256k1");
            }
            KeyType::Sr25519 => {
                // TODO: Validation
            }
            KeyType::X25519 => {
                // TODO: Validation
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for SignerBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerBytes")
            .field("key_type", &self.key_type)
            .field("bytes", &"<REDACTED>")
            .finish()
    }
}

/// Note that this only zeroes the private key material, not the key type.
impl std::ops::Drop for SignerBytes {
    fn drop(&mut self) {
        // No need to zeroize the key type.
        zeroize::Zeroize::zeroize(&mut self.byte_v);
    }
}

impl ExtractableSignerT for SignerBytes {
    fn extract_signer_bytes(&self) -> Result<SignerBytes> {
        Ok(self.clone())
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for SignerBytes {
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

impl SignerT for SignerBytes {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn key_type(&self) -> KeyType {
        self.key_type
    }
    fn get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        match self.key_type {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let signing_key = ed25519_dalek::SigningKey::try_from(self)?;
                    let verifying_key = signing_key.verifying_key();
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
                    let verifier_dyn_b: Box<dyn VerifierT> = Box::new(verifying_key);
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
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
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
                    use signature::Signer;
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
                    use signature::Signer;
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

/// The Drop impl handles the zeroization of the private key material.
impl zeroize::ZeroizeOnDrop for SignerBytes {}
