use crate::{Result, SignerBytes, SignerT};

/// Trait for signers whose private key material can be extracted.  In particular, this trait can't
/// be implemented for e.g. a hardware signing key or other non-extractable key.
///
/// See [AsAsyncExtractableSigner] for a wrapper type that allows a
/// `&(dyn ExtractableSignerT + Send + Sync)` to be used as an `AsyncExtractableSignerT`.
///
/// Related traits: [SignerT], [AsyncExtractableSignerT].
pub trait ExtractableSignerT: SignerT {
    /// Returns the SignerBytes representation of this ExtractableSignerT.
    fn extract_signer_bytes(&self) -> Result<SignerBytes>;
}
