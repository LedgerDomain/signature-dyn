use crate::{KeyType, Result, SignatureT, VerifierBytes, VerifierT};

/// Dyn-compatible trait for signers, i.e. private keys that can be used to sign messages.
///
/// Related traits:
/// - [ExtractableSignerT] for signers whose private key material can be extracted.
/// - [AsyncSignerT] for signers that can be used in asynchronous contexts.
/// - [SignerBytes] for the byte representation of a signer.
/// - [VerifierT] for the verifier corresponding to a signer.
/// - [VerifierBytes] for the byte representation of a verifier.
pub trait SignerT {
    /// Return the key id of this SignerT -- i.e. the value that should be used in the "kid" field
    /// of a JWS or other signed artifact.  If a key id is unavailable or undefined, return None.
    fn key_id(&self) -> Option<String>;
    /// Return the key type of this SignerT.
    fn key_type(&self) -> KeyType;
    /// Return the JOSE algorithm string for this SignerT type, e.g. "Ed25519", "Ed448", "ES256", "ES384", "ES512", "ES256K".
    #[deprecated(note = "use key_type().jose_algorithm() instead")]
    fn jose_algorithm(&self) -> &'static str {
        self.key_type().jose_algorithm()
    }
    // /// Return the byte representation of this SignerT.
    // fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]>;
    // /// Returns the SignerBytes representation of this SignerT, which is useful for interoperability.
    // fn to_signer_bytes<'b, 's: 'b>(&'s self) -> SignerBytes<'b> {
    //     SignerBytes::new(self.key_type(), self.bytes()).expect("Failed to create SignerBytes")
    // }
    /// Returns the corresponding verifier which can verify signatures that this SignerT produces.
    fn get_verifier(&self) -> Result<Box<dyn VerifierT>>;
    /// Returns the VerifierBytes representation of `self.verifier_dyn()`, i.e. its pub key.
    /// Default implementation calls `self.verifier_dyn()?.to_verifier_bytes()`.  Can be overridden
    /// to provide a more efficient implementation.
    fn get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.get_verifier()?.to_verifier_bytes().into_owned())
    }
    /// Attempt to sign the given message.
    fn try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>>;
    /// Sign the given message.  Default implementation calls try_sign_message and panics if it fails.
    #[deprecated(note = "use try_sign_message instead")]
    fn sign_message(&self, message_byte_v: &[u8]) -> Box<dyn SignatureT> {
        self.try_sign_message(message_byte_v)
            .expect("SignerT::sign_message failed")
    }
}
