use std::borrow::Cow;

use crate::{KeyType, Result, SignatureDynT, VerifierBytes};

pub trait VerifierDynT {
    fn key_type(&self) -> KeyType;
    fn jose_algorithm(&self) -> &'static str {
        self.key_type().jose_algorithm()
    }
    fn bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]>;
    fn to_verifier_bytes<'b, 's: 'b>(&'s self) -> VerifierBytes<'b> {
        VerifierBytes::new(self.key_type(), self.bytes()).expect("Failed to create VerifierBytes")
    }
    fn verify_message(&self, message_byte_v: &[u8], signature: &dyn SignatureDynT) -> Result<()>;
}
