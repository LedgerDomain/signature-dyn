use crate::{
    AsyncSignerT, ExtractableSignerT, KeyType, Result, SignatureT, SignerBytes, VerifierBytes,
    VerifierT,
};

/// Trait for signers whose private key material can be extracted in an asynchronous context.  In particular,
/// this trait can't be implemented for e.g. a hardware signing key or other non-extractable key.
///
/// See [AsAsyncExtractableSigner] for a wrapper type that allows a
/// `&(dyn ExtractableSignerT + Send + Sync)` to be used as an `AsyncExtractableSignerT`.
///
/// Related traits: [ExtractableSignerT], [AsyncSignerT].
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AsyncExtractableSignerT: AsyncSignerT {
    /// Returns the SignerBytes representation of this AsyncExtractableSignerT.
    async fn async_extract_signer_bytes(&self) -> Result<SignerBytes>;
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<S: AsyncSignerT + ExtractableSignerT + Send + Sync> AsyncExtractableSignerT for S {
    async fn async_extract_signer_bytes(&self) -> Result<SignerBytes> {
        self.extract_signer_bytes()
    }
}

/// Wrapper type to allow a `&(dyn ExtractableSignerT + Send + Sync)` to be used as an `AsyncExtractableSignerT`.
pub struct AsAsyncExtractableSigner<'a>(&'a (dyn ExtractableSignerT + Send + Sync));

impl<'a> AsAsyncExtractableSigner<'a> {
    pub fn new(extractable_signer: &'a (dyn ExtractableSignerT + Send + Sync)) -> Self {
        Self(extractable_signer)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'a> AsyncSignerT for AsAsyncExtractableSigner<'a> {
    async fn async_key_id(&self) -> Result<Option<String>> {
        Ok(self.0.key_id())
    }
    async fn async_key_type(&self) -> Result<KeyType> {
        Ok(self.0.key_type())
    }
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok(self.0.get_verifier()?)
    }
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.0.get_verifier_bytes()?)
    }
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        Ok(self.0.try_sign_message(message_byte_v)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'a> AsyncExtractableSignerT for AsAsyncExtractableSigner<'a> {
    async fn async_extract_signer_bytes(&self) -> Result<SignerBytes> {
        self.0.extract_signer_bytes()
    }
}
