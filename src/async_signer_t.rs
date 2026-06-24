use crate::{KeyType, Result, SignatureT, SignerT, VerifierBytes, VerifierT};

/// Trait for signers that can be used in asynchronous contexts.
///
/// See [AsAsyncSigner] for a wrapper type that allows a `&(dyn SignerT + Send + Sync)` to
/// be used as an `AsyncSignerT`.
///
/// Related traits: [SignerT], [AsyncExtractableSignerT].
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AsyncSignerT {
    /// Return the key id of this AsyncSignerT -- i.e. the value that should be used in the "kid" field
    /// of a JWS or other signed artifact.  If a key id is unavailable or undefined, return None.
    async fn async_key_id(&self) -> Result<Option<String>>;
    /// Return the key type of this AsyncSignerT.
    async fn async_key_type(&self) -> Result<KeyType>;
    /// Returns the corresponding verifier which can verify signatures that this AsyncSignerT produces.
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>>;
    /// Returns the VerifierBytes representation of `self.verifier_dyn()`, i.e. its pub key.
    /// Default implementation calls `self.verifier_dyn()?.to_verifier_bytes()`.  Can be overridden
    /// to provide a more efficient implementation.
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self
            .async_get_verifier()
            .await?
            .to_verifier_bytes()
            .into_owned())
    }
    /// Attempt to sign the given message.
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>>;
}

/// A SignerT has a canonical implementation of AsyncSignerT.
///
/// This impl is here instead of in signer_t.rs because it's gated behind the "async" feature.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<S: SignerT + Send + Sync> AsyncSignerT for S {
    async fn async_key_id(&self) -> Result<Option<String>> {
        Ok(self.key_id())
    }
    async fn async_key_type(&self) -> Result<KeyType> {
        Ok(self.key_type())
    }
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok(self.get_verifier()?)
    }
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.get_verifier_bytes()?)
    }
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        Ok(self.try_sign_message(message_byte_v)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl AsyncSignerT for dyn SignerT + Send + Sync {
    async fn async_key_id(&self) -> Result<Option<String>> {
        Ok((*self).key_id())
    }
    async fn async_key_type(&self) -> Result<KeyType> {
        Ok((*self).key_type())
    }
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok((*self).get_verifier()?)
    }
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok((*self).get_verifier_bytes()?)
    }
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        Ok((*self).try_sign_message(message_byte_v)?)
    }
}

/// Wrapper type to allow a `&(dyn SignerT + Send + Sync)` to be used as an `AsyncSignerT`.
pub struct AsAsyncSigner<'a>(&'a (dyn SignerT + Send + Sync));

impl<'a> AsAsyncSigner<'a> {
    pub fn new(signer: &'a (dyn SignerT + Send + Sync)) -> Self {
        Self(signer)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'a> AsyncSignerT for AsAsyncSigner<'a> {
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
