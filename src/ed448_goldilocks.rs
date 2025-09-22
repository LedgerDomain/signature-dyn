use std::borrow::Cow;

use crate::{
    ED448_JOSE_ALGORITHM, KeyType, Result, SignatureBytes, SignatureDynT, SignerBytes, SignerDynT,
    VerifierBytes, VerifierDynT, ensure, error,
};

//
// Signature
//

impl SignatureDynT for ed448_goldilocks::Signature {
    fn jose_algorithm(&self) -> &'static str {
        ED448_JOSE_ALGORITHM
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
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
        let signature_byte_v = signature_bytes.bytes();
        Ok(ed448_goldilocks::Signature::from_slice(
            signature_byte_v.as_ref(),
        )?)
    }
}

//
// SigningKey
//

#[cfg(feature = "random")]
impl crate::GenerateRandom for ed448_goldilocks::SigningKey {
    fn generate_random() -> Self {
        ed448_goldilocks::SigningKey::generate(&mut rand_0_9::rand_core::UnwrapMut(
            &mut rand_0_9::rngs::OsRng,
        ))
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Read for ed448_goldilocks::SigningKey {
    fn read_from_pkcs8_pem_file(path: &std::path::Path) -> Result<Self> {
        use pkcs8_0_11::DecodePrivateKey;
        Ok(ed448_goldilocks::SigningKey::read_pkcs8_pem_file(path)?)
    }
}

#[cfg(feature = "pkcs8")]
impl crate::PKCS8Write for ed448_goldilocks::SigningKey {
    fn write_to_pkcs8_pem_file(&self, path: &std::path::Path) -> Result<()> {
        use pkcs8_0_11::EncodePrivateKey;
        Ok(self.write_pkcs8_pem_file(path, Default::default())?)
    }
}

impl SignerDynT for ed448_goldilocks::SigningKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed448
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
        use signature_3::Signer;
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

impl VerifierDynT for ed448_goldilocks::VerifyingKey {
    fn key_type(&self) -> KeyType {
        KeyType::Ed448
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.as_bytes().as_slice().into()
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureDynT) -> Result<()> {
        ensure!(
            signature.jose_algorithm() == ED448_JOSE_ALGORITHM,
            "expected signature algorithm to be {:?}, but got {:?}",
            ED448_JOSE_ALGORITHM,
            signature.jose_algorithm(),
        );
        let signature_bytes = signature.to_signature_bytes();
        let signature = ed448_goldilocks::Signature::try_from(&signature_bytes)?;
        use signature_3::Verifier;
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
        let verifier_byte_v = verifier_bytes.bytes();
        let byte_array = <&[u8; 57]>::try_from(verifier_byte_v.as_ref())?;
        ed448_goldilocks::VerifyingKey::from_bytes(byte_array)
            .map_err(|e| error!("failed to convert VerifierBytes to VerifyingKey: {}", e))
    }
}
