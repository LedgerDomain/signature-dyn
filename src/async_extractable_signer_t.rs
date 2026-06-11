use std::borrow::Cow;

use crate::{AsyncSignerT, ExtractableSignerT, Result, SignerBytes};

/// Trait for signers whose private key material can be extracted.  In particular, this trait can't be implemented
/// for e.g. a hardware signing key or other non-extractable key.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AsyncExtractableSignerT: AsyncSignerT {
    /// Return the raw byte representation of this AsyncExtractableSignerT.
    async fn async_extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>>;
    /// Returns the SignerBytes representation of this AsyncExtractableSignerT, which is useful for interoperability.
    async fn async_extract_signer_bytes<'b, 's: 'b>(&'s self) -> Result<SignerBytes<'b>> {
        Ok(SignerBytes::new(
            self.async_key_type().await?,
            self.async_extract_raw_bytes().await?,
        )?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<S: ExtractableSignerT + Send + Sync> AsyncExtractableSignerT for S {
    async fn async_extract_raw_bytes<'b, 's: 'b>(&'s self) -> Result<Cow<'b, [u8]>> {
        Ok(self.extract_raw_bytes()?)
    }
    async fn async_extract_signer_bytes<'b, 's: 'b>(&'s self) -> Result<SignerBytes<'b>> {
        Ok(self.extract_signer_bytes()?)
    }
}
