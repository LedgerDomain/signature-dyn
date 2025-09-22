use std::borrow::Cow;

use crate::{KeyType, Result, SignatureDynT, SignerBytes, VerifierBytes, VerifierDynT};

pub trait SignerDynT {
    /// Return the key type of this SignerDynT.
    fn key_type(&self) -> KeyType;
    /// Return the JOSE algorithm string for this SignerDynT type, e.g. "Ed25519", "Ed448", "ES256", "ES384", "ES512", "ES256K".
    fn jose_algorithm(&self) -> &'static str {
        self.key_type().jose_algorithm()
    }
    /// Return the byte representation of this SignerDynT.
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]>;
    /// Returns the SignerBytes representation of this SignerDynT, which is useful for interoperability.
    fn to_signer_bytes<'b, 's: 'b>(&'s self) -> SignerBytes<'b> {
        SignerBytes::new(self.key_type(), self.bytes()).expect("Failed to create SignerBytes")
    }
    /// Returns the corresponding verifier which can verify signatures that this SignerDynT produces.
    fn verifier_dyn(&self) -> Result<Box<dyn VerifierDynT>>;
    /// Returns the VerifierBytes representation of `self.verifier_dyn()`, i.e. its pub key.
    /// Default implementation calls `self.verifier_dyn()?.to_verifier_bytes()`.  Can be overridden
    /// to provide a more efficient implementation.
    fn verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.verifier_dyn()?.to_verifier_bytes().into_owned())
    }
    /// Attempt to sign the given message.
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureDynT>>;
    /// Sign the given message.  Default implementation calls try_sign_message and panics if it fails.
    fn sign_message(&self, message_byte_v: &[u8]) -> Box<dyn SignatureDynT> {
        self.try_sign_message(message_byte_v)
            .expect("SignerDynT::sign_message failed")
    }
}
