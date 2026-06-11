use std::borrow::Cow;

use crate::{
    ED448_JOSE_ALGORITHM, ExtractableSignerT, KeyType, Result, SignatureBytes, SignatureT,
    SignerBytes, SignerT, VerifierBytes, VerifierT, ensure, error,
};

//
// Signature
//

impl SignatureT for ed448_goldilocks::Signature {
    fn jose_algorithm(&self) -> &'static str {
        ED448_JOSE_ALGORITHM
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.to_bytes().to_vec().into()
    }
}

impl TryFrom<&SignatureBytes<'_>> for ed448_goldilocks::Signature {
    type Error = crate::Error;
    fn try_from(signature_bytes: &SignatureBytes<'_>) -> Result<Self> {
        ensure!(
            signature_bytes.jose_algorithm() == ED448_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            ED448_JOSE_ALGORITHM,
            signature_bytes.jose_algorithm(),
        );
        let signature_byte_v = signature_bytes.get_raw_bytes();
        Ok(ed448_goldilocks::Signature::from_slice(
            signature_byte_v.as_ref(),
        )?)
    }
}

//
// SigningKey
//

impl ExtractableSignerT for ed448_goldilocks::SigningKey {
    fn extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>> {
        Ok(self.as_bytes().as_slice().into())
    }
}

#[cfg(feature = "random")]
impl crate::GenerateRandom for ed448_goldilocks::SigningKey {
    fn generate_random() -> Self {
        use ed448_goldilocks::elliptic_curve::Generate;
        ed448_goldilocks::SigningKey::generate()
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Read for ed448_goldilocks::SigningKey {
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        Ok(ed448_goldilocks::SigningKey::read_pkcs8_pem_file(path)?)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for ed448_goldilocks::SigningKey {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        use pkcs8::EncodePrivateKey;
        Ok(self.write_pkcs8_pem_file(path, Default::default())?)
    }
}

impl SignerT for ed448_goldilocks::SigningKey {
    fn key_id(&self) -> Option<String> {
        None
    }
    fn key_type(&self) -> KeyType {
        KeyType::Ed448
    }
    fn get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok(Box::new(self.verifying_key()))
    }
    fn get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifying_key().to_verifier_bytes().into_owned())
    }
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        use signature::Signer;
        let signature: ed448_goldilocks::Signature = self.try_sign(message_byte_v)?;
        Ok(Box::new(signature))
    }
}

impl TryFrom<&SignerBytes<'_>> for ed448_goldilocks::SigningKey {
    type Error = crate::Error;
    fn try_from(signer_bytes: &SignerBytes<'_>) -> Result<Self> {
        ensure!(
            signer_bytes.key_type() == KeyType::Ed448,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Ed448,
            signer_bytes.key_type(),
        );
        let signer_byte_v = signer_bytes.bytes();
        ed448_goldilocks::SigningKey::try_from(signer_byte_v.as_ref())
            .map_err(|e| error!("failed to convert SignerBytes to SigningKey: {}", e))
    }
}

//
// VerifyingKey
//

impl VerifierT for ed448_goldilocks::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed448
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.as_bytes().as_slice().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureT) -> Result<()> {
        ensure!(
            signature.jose_algorithm() == ED448_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            ED448_JOSE_ALGORITHM,
            signature.jose_algorithm(),
        );
        let signature_bytes = signature.to_signature_bytes();
        let signature = ed448_goldilocks::Signature::try_from(&signature_bytes)?;
        use signature::Verifier;
        self.verify(message_byte_v, &signature).map_err(|e| {
            error!(
                "{:?} signature verification failed: {}",
                ED448_JOSE_ALGORITHM, e
            )
        })
    }
}

impl TryFrom<&VerifierBytes<'_>> for ed448_goldilocks::VerifyingKey {
    type Error = crate::Error;
    fn try_from(verifier_bytes: &VerifierBytes<'_>) -> Result<Self> {
        ensure!(
            verifier_bytes.key_type() == KeyType::Ed448,
            "expected key type to be {:?}, but got {:?}",
            KeyType::Ed448,
            verifier_bytes.key_type(),
        );
        let verifier_byte_v = verifier_bytes.get_raw_bytes();
        let byte_array = <&[u8; 57]>::try_from(verifier_byte_v.as_ref())?;
        ed448_goldilocks::VerifyingKey::from_bytes(byte_array)
            .map_err(|e| error!("failed to convert VerifierBytes to VerifyingKey: {}", e))
    }
}
