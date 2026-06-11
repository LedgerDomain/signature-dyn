use std::borrow::Cow;

use crate::{
    ExtractableSignerT, KeyType, Result, SECP256K1_JOSE_ALGORITHM, SignatureBytes, SignatureT,
    SignerBytes, SignerT, VerifierBytes, VerifierT, ensure, error,
};

//
// Signature
//

impl SignatureT for k256::ecdsa::Signature {
    fn jose_algorithm(&self) -> &'static str {
        SECP256K1_JOSE_ALGORITHM
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
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
        let signature_byte_v = signature_bytes.get_raw_bytes();
        Ok(k256::ecdsa::Signature::from_slice(
            signature_byte_v.as_ref(),
        )?)
    }
}

//
// SigningKey
//

impl ExtractableSignerT for k256::ecdsa::SigningKey {
    fn extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>> {
        #[allow(deprecated)]
        Ok(self.to_bytes().as_slice().to_vec().into())
    }
}

#[cfg(feature = "random")]
impl crate::GenerateRandom for k256::ecdsa::SigningKey {
    fn generate_random() -> Self {
        use k256::elliptic_curve::Generate;
        k256::ecdsa::SigningKey::generate()
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

impl SignerT for k256::ecdsa::SigningKey {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok(Box::new(self.verifying_key().clone()))
    }
    fn get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifying_key().to_verifier_bytes().into_owned())
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
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
        let signer_byte_v = signer_bytes.extract_raw_bytes()?;
        Ok(k256::ecdsa::SigningKey::from_slice(signer_byte_v.as_ref())?)
    }
}

//
// VerifyingKey
//

impl VerifierT for k256::ecdsa::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_sec1_bytes().into_vec().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureT) -> Result<()> {
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
        let verifier_byte_v = verifier_bytes.get_raw_bytes();
        Ok(k256::ecdsa::VerifyingKey::from_sec1_bytes(
            verifier_byte_v.as_ref(),
        )?)
    }
}
