use std::borrow::Cow;

use crate::{
    KeyType, Result, SECP256K1_JOSE_ALGORITHM, SignatureBytes, SignatureDynT, SignerBytes,
    SignerDynT, VerifierBytes, VerifierDynT, ensure, error,
};

//
// Signature
//

impl SignatureDynT for k256::ecdsa::Signature {
    fn jose_algorithm(&self) -> &'static str {
        SECP256K1_JOSE_ALGORITHM
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_vec().into()
    }
}

impl TryFrom<&SignatureBytes<'_>> for k256::ecdsa::Signature {
    type Error = crate::Error;
    fn try_from(signature_bytes: &SignatureBytes<'_>) -> Result<Self> {
        ensure!(
            signature_bytes.jose_algorithm() == SECP256K1_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            SECP256K1_JOSE_ALGORITHM,
            signature_bytes.jose_algorithm(),
        );
        let signature_byte_v = signature_bytes.bytes();
        Ok(k256::ecdsa::Signature::from_slice(
            signature_byte_v.as_ref(),
        )?)
    }
}

//
// SigningKey
//

#[cfg(feature = "random")]
impl crate::GenerateRandom for k256::ecdsa::SigningKey {
    fn generate_random() -> Self {
        k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Read for k256::ecdsa::SigningKey {
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        Ok(k256::ecdsa::SigningKey::read_pkcs8_pem_file(path)?)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for k256::ecdsa::SigningKey {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        use pkcs8::EncodePrivateKey;
        Ok(self.write_pkcs8_pem_file(path, Default::default())?)
    }
}

impl SignerDynT for k256::ecdsa::SigningKey {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_bytes().as_slice().to_vec().into()
    }
    fn verifier_dyn(&self) -> Result<Box<dyn VerifierDynT>> {
        Ok(Box::new(self.verifying_key().clone()))
    }
    fn verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifying_key().to_verifier_bytes().into_owned())
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureDynT>> {
        use signature::Signer;
        let signature: k256::ecdsa::Signature = self.try_sign(message_byte_v)?;
        Ok(Box::new(signature))
    }
}

impl TryFrom<&SignerBytes<'_>> for k256::ecdsa::SigningKey {
    type Error = crate::Error;
    fn try_from(signer_bytes: &SignerBytes<'_>) -> Result<Self> {
        ensure!(
            signer_bytes.key_type() == KeyType::Secp256k1,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Secp256k1,
            signer_bytes.key_type(),
        );
        let signer_byte_v = signer_bytes.bytes();
        Ok(k256::ecdsa::SigningKey::from_slice(signer_byte_v.as_ref())?)
    }
}

//
// VerifyingKey
//

impl VerifierDynT for k256::ecdsa::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_sec1_bytes().into_vec().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureDynT) -> Result<()> {
        ensure!(
            signature.jose_algorithm() == SECP256K1_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            SECP256K1_JOSE_ALGORITHM,
            signature.jose_algorithm(),
        );
        let signature_bytes = signature.to_signature_bytes();
        let signature = k256::ecdsa::Signature::try_from(&signature_bytes)?;
        use signature::Verifier;
        self.verify(message_byte_v, &signature).map_err(|e| {
            error!(
                "{:?} signature verification failed: {}",
                SECP256K1_JOSE_ALGORITHM, e
            )
        })
    }
}

impl TryFrom<&VerifierBytes<'_>> for k256::ecdsa::VerifyingKey {
    type Error = crate::Error;
    fn try_from(verifier_bytes: &VerifierBytes<'_>) -> Result<Self> {
        ensure!(
            verifier_bytes.key_type() == KeyType::Secp256k1,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Secp256k1,
            verifier_bytes.key_type(),
        );
        let verifier_byte_v = verifier_bytes.bytes();
        Ok(k256::ecdsa::VerifyingKey::from_sec1_bytes(
            verifier_byte_v.as_ref(),
        )?)
    }
}
