use std::borrow::Cow;

use zeroize::Zeroizing;

use crate::{
    ExtractableSignerT, KeyType, P521_JOSE_ALGORITHM, Result, SignatureBytes, SignatureT,
    SignerBytes, SignerT, VerifierBytes, VerifierT, ensure, error,
};

//
// Signature
//

impl SignatureT for p521::ecdsa::Signature {
    fn jose_algorithm(&self) -> &'static str {
        P521_JOSE_ALGORITHM
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_vec().into()
    }
}

impl TryFrom<&SignatureBytes<'_>> for p521::ecdsa::Signature {
    type Error = crate::Error;
    fn try_from(signature_bytes: &SignatureBytes<'_>) -> Result<Self> {
        ensure!(
            signature_bytes.jose_algorithm() == P521_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            P521_JOSE_ALGORITHM,
            signature_bytes.jose_algorithm(),
        );
        let signature_byte_v = signature_bytes.get_raw_bytes();
        Ok(p521::ecdsa::Signature::from_slice(
            signature_byte_v.as_ref(),
        )?)
    }
}

//
// SigningKey
//

impl ExtractableSignerT for p521::ecdsa::SigningKey {
    fn extract_signer_bytes(&self) -> Result<SignerBytes> {
        SignerBytes::new(
            KeyType::P521,
            Zeroizing::new(self.to_bytes().as_slice().to_vec()),
        )
    }
}

#[cfg(feature = "random")]
impl crate::GenerateRandom for p521::ecdsa::SigningKey {
    fn generate_random() -> Self {
        use p521::elliptic_curve::Generate;
        p521::ecdsa::SigningKey::generate()
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Read for p521::ecdsa::SigningKey {
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        Ok(p521::ecdsa::SigningKey::read_pkcs8_pem_file(path)?)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for p521::ecdsa::SigningKey {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        use pkcs8::EncodePrivateKey;
        Ok(self.write_pkcs8_pem_file(path, Default::default())?)
    }
}

impl SignerT for p521::ecdsa::SigningKey {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn key_type(&self) -> KeyType {
        KeyType::P521
    }
    fn get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        let verifying_key = p521::ecdsa::VerifyingKey::from(self);
        Ok(Box::new(verifying_key))
    }
    fn get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifying_key().to_verifier_bytes().into_owned())
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        use signature::Signer;
        let signature: p521::ecdsa::Signature = self.try_sign(message_byte_v)?;
        Ok(Box::new(signature))
    }
}

impl TryFrom<&SignerBytes> for p521::ecdsa::SigningKey {
    type Error = crate::Error;
    fn try_from(signer_bytes: &SignerBytes) -> Result<Self> {
        ensure!(
            signer_bytes.key_type() == KeyType::P521,
            "expected key type to be {:?}, but got {:?}",
            KeyType::P521,
            signer_bytes.key_type(),
        );
        Ok(p521::ecdsa::SigningKey::from_slice(signer_bytes.bytes())?)
    }
}

//
// VerifyingKey
//

impl VerifierT for p521::ecdsa::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::P521
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_sec1_bytes().into_vec().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureT) -> Result<()> {
        ensure!(
            signature.jose_algorithm() == P521_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            P521_JOSE_ALGORITHM,
            signature.jose_algorithm(),
        );
        let signature_bytes = signature.to_signature_bytes();
        let signature = p521::ecdsa::Signature::try_from(&signature_bytes)?;
        use signature::Verifier;
        self.verify(message_byte_v, &signature).map_err(|e| {
            error!(
                "{:?} signature verification failed: {}",
                P521_JOSE_ALGORITHM, e
            )
        })
    }
}

impl TryFrom<&VerifierBytes<'_>> for p521::ecdsa::VerifyingKey {
    type Error = crate::Error;
    fn try_from(verifier_bytes: &VerifierBytes<'_>) -> Result<Self> {
        ensure!(
            verifier_bytes.key_type() == KeyType::P521,
            "expected key type to be {:?}, but got {:?}",
            KeyType::P521,
            verifier_bytes.key_type(),
        );
        let verifier_byte_v = verifier_bytes.bytes();
        Ok(p521::ecdsa::VerifyingKey::from_sec1_bytes(
            verifier_byte_v.as_ref(),
        )?)
    }
}
