use std::borrow::Cow;

use crate::{
    KeyType, Result, SignatureT, SignerT, VerifierT, extractable_signer_t::ExtractableSignerT,
};

/// This is a generic data structure to represent private keys that doesn't require direct use of the underlying
/// cryptographic libraries.  This is useful for serialization and deserialization of private keys.
#[derive(Clone, Eq, PartialEq)]
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
    pub fn into_owned<'b>(mut self) -> SignerBytes<'b> {
        // This dummy and swap business is because ZeroizeOnDrop impls Drop for this
        // type, and that prevents moving out of self.
        let mut dummy = Cow::Borrowed(&[] as &[u8]);
        std::mem::swap(&mut dummy, &mut self.byte_v);
        let byte_v = dummy.into_owned();
        SignerBytes::<'b> {
            key_type: self.key_type,
            byte_v: Cow::Owned(byte_v),
        }
    }
    pub fn to_owned<'b>(&self) -> SignerBytes<'b> {
        SignerBytes {
            key_type: self.key_type.clone(),
            byte_v: Cow::Owned(self.byte_v.to_vec()),
        }
    }
}

impl<'a> std::fmt::Debug for SignerBytes<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerBytes")
            .field("key_type", &self.key_type)
            .field("bytes", &"<REDACTED>")
            .finish()
    }
}

/// Note that this only zeroes the private key material, not the key type.
impl<'a> std::ops::Drop for SignerBytes<'a> {
    fn drop(&mut self) {
        // No need to zeroize the key type.

        let mut dummy = Cow::Borrowed(&[] as &[u8]);
        std::mem::swap(&mut dummy, &mut self.byte_v);
        // dummy now contains the original content of self.byte_v, which we can zeroize
        // if it's a Cow::Owned.  If it's a Cow::Borrowed, we can't zeroize it, but ostensibly
        // it was borrowed from something that impls ZeroizeOnDrop.
        if let Cow::Owned(mut byte_v) = dummy {
            zeroize::Zeroize::zeroize(&mut byte_v);
        }
    }
}

impl<'a> ExtractableSignerT for SignerBytes<'a> {
    fn extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>> {
        Ok(Cow::Borrowed(self.bytes()))
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

impl<'a> SignerT for SignerBytes<'a> {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn key_type(&self) -> KeyType {
        self.key_type
    }
    // fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
    //     self.byte_v.clone()
    // }
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
    // fn to_signer_bytes<'b, 's: 'b>(&'s self) -> SignerBytes<'b> {
    //     self.clone()
    // }
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
impl<'a> zeroize::ZeroizeOnDrop for SignerBytes<'a> {}
