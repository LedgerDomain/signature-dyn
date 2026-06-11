use std::borrow::Cow;

use crate::{Result, SignerBytes, SignerT};

/// Trait for signers whose private key material can be extracted.  In particular, this trait can't be implemented
/// for e.g. a hardware signing key or other non-extractable key.
pub trait ExtractableSignerT: SignerT {
    /// Return the raw byte representation of this ExtractableSignerT.
    fn extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>>;
    /// Returns the SignerBytes representation of this ExtractableSignerT, which is useful for interoperability.
    fn extract_signer_bytes<'b, 's: 'b>(&'s self) -> Result<SignerBytes<'b>> {
        Ok(SignerBytes::new(
            self.key_type(),
            self.extract_raw_bytes()?,
        )?)
    }
}
