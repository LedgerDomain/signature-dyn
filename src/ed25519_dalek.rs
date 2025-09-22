use std::borrow::Cow;

use crate::{
    KeyType, Result, SignatureBytes, SignatureDynT, SignerBytes, SignerDynT, VerifierBytes,
    VerifierDynT, ensure, error,
};

//
// Signature
//

/// See <https://www.iana.org/assignments/jose/jose.xhtml>
pub const ED25519_JOSE_ALGORITHM: &str = "Ed25519";

impl SignatureDynT for ed25519_dalek::Signature {
    fn jose_algorithm(&self) -> &'static str {
        ED25519_JOSE_ALGORITHM
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_vec().into()
    }
}

impl TryFrom<&SignatureBytes<'_>> for ed25519_dalek::Signature {
    type Error = crate::Error;
    fn try_from(signature_bytes: &SignatureBytes<'_>) -> Result<Self> {
        ensure!(
            signature_bytes.jose_algorithm() == ED25519_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            ED25519_JOSE_ALGORITHM,
            signature_bytes.jose_algorithm(),
        );
        let signature_byte_v = signature_bytes.bytes();
        let byte_array = <&[u8; 64]>::try_from(signature_byte_v.as_ref())?;
        Ok(ed25519_dalek::Signature::from_bytes(byte_array))
    }
}

//
// SigningKey
//

#[cfg(feature = "random")]
impl crate::GenerateRandom for ed25519_dalek::SigningKey {
    fn generate_random() -> Self {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Read for ed25519_dalek::SigningKey {
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        Ok(ed25519_dalek::SigningKey::read_pkcs8_pem_file(path)?)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for ed25519_dalek::SigningKey {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        use pkcs8::EncodePrivateKey;
        Ok(self.write_pkcs8_pem_file(path, Default::default())?)
    }
}

impl SignerDynT for ed25519_dalek::SigningKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.as_bytes().as_slice().into()
    }
    fn verifier_dyn(&self) -> Result<Box<dyn VerifierDynT>> {
        Ok(Box::new(self.verifying_key()))
    }
    fn verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifying_key().to_verifier_bytes().into_owned())
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureDynT>> {
        use signature::Signer;
        Ok(Box::new(self.try_sign(message_byte_v)?))
    }
}

impl TryFrom<&SignerBytes<'_>> for ed25519_dalek::SigningKey {
    type Error = crate::Error;
    fn try_from(signer_bytes: &SignerBytes<'_>) -> Result<Self> {
        ensure!(
            signer_bytes.key_type() == KeyType::Ed25519,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Ed25519,
            signer_bytes.key_type(),
        );
        let signer_byte_v = signer_bytes.bytes();
        let byte_array = <&[u8; 32]>::try_from(signer_byte_v.as_ref())?;
        Ok(ed25519_dalek::SigningKey::from_bytes(byte_array))
    }
}

//
// VerifyingKey
//

impl VerifierDynT for ed25519_dalek::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.as_bytes().as_slice().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureDynT) -> Result<()> {
        ensure!(
            signature.jose_algorithm() == ED25519_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            ED25519_JOSE_ALGORITHM,
            signature.jose_algorithm(),
        );
        let signature = ed25519_dalek::Signature::try_from(signature.bytes().as_ref())?;
        use signature::Verifier;
        self.verify(message_byte_v, &signature).map_err(|e| {
            error!(
                "{:?} signature verification failed: {}",
                ED25519_JOSE_ALGORITHM, e
            )
        })
    }
}

impl TryFrom<&VerifierBytes<'_>> for ed25519_dalek::VerifyingKey {
    type Error = crate::Error;
    fn try_from(verifier_bytes: &VerifierBytes<'_>) -> Result<Self> {
        ensure!(
            verifier_bytes.key_type() == KeyType::Ed25519,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Ed25519,
            verifier_bytes.key_type(),
        );
        let verifier_byte_v = verifier_bytes.bytes();
        let byte_array = <&[u8; 32]>::try_from(verifier_byte_v.as_ref())?;
        Ok(ed25519_dalek::VerifyingKey::from_bytes(byte_array)?)
    }
}
